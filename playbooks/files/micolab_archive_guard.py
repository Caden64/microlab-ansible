#!/usr/bin/env python3
"""Read-only validation of a MicroLab recovery tar archive.

The restore path must never extract an arbitrary archive to ``/``.  This
module enumerates every tar member and enforces a canonical allowlist:

* member names must be relative, canonical, and under a configured allowed
  root;
* regular files, directories, symlinks, and hardlinks are the only accepted
  member kinds;
* symlink and hardlink targets are canonicalized against the archive root and
  must also be under the allowlist;
* a member may not live below a symlink ancestor (the classic tar traversal
  trick);
* documented offline-root escrow names, including every ``root_ca_private*``
  variant, are rejected;
* required files/directories must exist with the expected member kind.

The guard never extracts and never writes to the archive.  It can be run as a
standalone script (``--spec-json``) or imported by the restore/backup helpers.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import posixpath
import re
import sys
import tarfile
from dataclasses import dataclass
from typing import Any, Iterable


DEFAULT_FORBIDDEN_PATTERNS = [
    r"(^|/)(root_ca_key[^/]*|root_ca\.key[^/]*|root_ca_private[^/]*|offline[-_]root[^/]*)(/|$)",
]

class GuardError(Exception):
    """The archive or the guard specification cannot be inspected."""


@dataclass(frozen=True)
class Member:
    name: str
    kind: str
    linkname: str
    mode: int


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise GuardError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def canonical_absolute_root(path: str) -> str:
    """Return a canonical absolute root without a trailing slash."""

    if not isinstance(path, str) or not path.startswith("/"):
        raise GuardError(f"allowlist root is not absolute: {path!r}")
    if "\x00" in path:
        raise GuardError("allowlist root contains NUL")
    normal = posixpath.normpath(path)
    if normal == "//":
        normal = "/"
    if normal != "/" and normal.endswith("/"):
        normal = normal.rstrip("/")
    if normal != path.rstrip("/") and normal != path:
        raise GuardError(f"allowlist root is not canonical: {path!r}")
    return normal


def archive_name(path: str) -> str:
    """Return the canonical archive-relative name for an absolute path."""

    root = canonical_absolute_root(path)
    return "" if root == "/" else root.lstrip("/")


def canonical_member(name: str) -> str:
    """Validate and return a canonical archive member name."""

    if not isinstance(name, str) or not name:
        raise GuardError("empty archive member name")
    if "\x00" in name:
        raise GuardError("archive member name contains NUL")
    if name.startswith("/"):
        raise GuardError(f"absolute archive member: {name!r}")
    stripped = name[:-1] if name.endswith("/") else name
    if not stripped:
        raise GuardError(f"empty archive member: {name!r}")
    if stripped.startswith("./") or stripped == ".":
        raise GuardError(f"non-canonical archive member: {name!r}")
    parts = stripped.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise GuardError(f"non-canonical archive member: {name!r}")
    return stripped


def is_within(path: str, root: str) -> bool:
    """True when absolute ``path`` equals or lies below absolute ``root``."""

    if root == "/":
        return path.startswith("/")
    return path == root or path.startswith(root + "/")


def member_absolute(name: str) -> str:
    return "/" + name


def forbidden_hits(value: str, patterns: Iterable[str]) -> list[str]:
    hits: list[str] = []
    for pattern in patterns:
        try:
            if re.search(pattern, value):
                hits.append(pattern)
        except re.error as exc:
            raise GuardError(f"invalid forbidden pattern {pattern!r}: {exc}") from exc
    return hits


def _member_kind(member: tarfile.TarInfo) -> str:
    if member.isdir():
        return "dir"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    if member.isreg():
        return "file"
    return "special"


def read_members(path: str) -> list[Member]:
    members: list[Member] = []
    try:
        with tarfile.open(path, mode="r:*") as archive:
            for member in archive:
                kind = _member_kind(member)
                members.append(
                    Member(
                        name=member.name,
                        kind=kind,
                        linkname=member.linkname or "",
                        mode=member.mode,
                    )
                )
    except (OSError, tarfile.TarError) as exc:
        raise GuardError(f"cannot read archive {path}: {exc}") from exc
    return members


def _link_target_absolute(member: Member) -> str:
    """Canonical absolute target for a symlink or hardlink member."""

    if member.kind == "hardlink":
        if not member.linkname:
            raise GuardError(f"empty hardlink target for {member.name!r}")
        if member.linkname.startswith("/"):
            raise GuardError(
                f"absolute hardlink target for {member.name!r}: {member.linkname!r}"
            )
        target_name = canonical_member(member.linkname)
        return member_absolute(target_name)

    if member.kind == "symlink":
        if not member.linkname:
            raise GuardError(f"empty symlink target for {member.name!r}")
        if "\x00" in member.linkname:
            raise GuardError(f"NUL in symlink target for {member.name!r}")
        if member.linkname.startswith("/"):
            target = posixpath.normpath(member.linkname)
        else:
            base = posixpath.dirname(member_absolute(member.name))
            target = posixpath.normpath(posixpath.join(base, member.linkname))
        if not target.startswith("/"):
            raise GuardError(
                f"symlink target escapes the archive root for {member.name!r}"
            )
        return target

    raise GuardError(f"{member.name!r} is not a link")


def validate_archive(
    path: str,
    allowed_roots: Iterable[str],
    required_members: Iterable[str] = (),
    required_files: Iterable[str] = (),
    required_dirs: Iterable[str] = (),
    forbidden_patterns: Iterable[str] | None = None,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate an archive and return a JSON-serializable result."""

    violations: list[str] = []
    try:
        roots = [canonical_absolute_root(root) for root in allowed_roots]
    except GuardError as exc:
        return _result(path, 0, [str(exc)], [], None)
    if not roots:
        return _result(path, 0, ["no allowed roots configured"], [], None)
    nested_violations: list[str] = []
    for index, root in enumerate(roots):
        for other_index, other in enumerate(roots):
            if index >= other_index:
                continue
            if is_within(root, other) or is_within(other, root):
                nested_violations.append(
                    f"allowlist roots must not nest: {root} and {other}"
                )
    if nested_violations:
        return _result(path, 0, nested_violations, [], None)

    actual_sha256: str | None = None
    if expected_sha256:
        expected = expected_sha256.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            return _result(path, 0, ["expected SHA-256 is not 64 hex characters"], [], None)
        try:
            actual_sha256 = sha256_file(path)
        except GuardError as exc:
            return _result(path, 0, [str(exc)], [], None)
        if actual_sha256 != expected:
            violations.append(
                f"archive SHA-256 {actual_sha256} does not match expected {expected}"
            )
    else:
        try:
            actual_sha256 = sha256_file(path)
        except GuardError:
            actual_sha256 = None

    patterns = (
        list(DEFAULT_FORBIDDEN_PATTERNS)
        if forbidden_patterns is None
        else list(forbidden_patterns)
    )

    try:
        members = read_members(path)
    except GuardError as exc:
        return _result(path, 0, violations + [str(exc)], [], actual_sha256)

    names: dict[str, Member] = {}
    for member in members:
        try:
            name = canonical_member(member.name)
        except GuardError as exc:
            violations.append(str(exc))
            continue
        absolute = member_absolute(name)
        if not any(is_within(absolute, root) for root in roots):
            violations.append(f"member is outside the restore allowlist: {name}")
        for pattern in forbidden_hits(name, patterns):
            violations.append(
                f"forbidden offline-root material {name!r} matches {pattern!r}"
            )

        if member.kind == "special":
            violations.append(f"special file type is not allowed: {name}")
            continue
        if member.kind in ("symlink", "hardlink"):
            try:
                target = _link_target_absolute(member)
            except GuardError as exc:
                violations.append(str(exc))
                continue
            if not any(is_within(target, root) for root in roots):
                violations.append(
                    f"{member.kind} target escapes the allowlist: "
                    f"{name} -> {target}"
                )
            target_name = target.lstrip("/")
            for pattern in forbidden_hits(target_name, patterns):
                violations.append(
                    f"{member.kind} target is forbidden offline-root material: "
                    f"{name} -> {target}"
                )

        if name in names:
            violations.append(f"duplicate archive member: {name}")
        else:
            names[name] = Member(
                name=name,
                kind=member.kind,
                linkname=member.linkname,
                mode=member.mode,
            )

    # Reject a file or link used as a directory ancestor.  This catches both
    # malicious archives and malformed ones before extraction.
    for name in names:
        parts = name.split("/")
        for index in range(1, len(parts)):
            ancestor = "/".join(parts[:index])
            holder = names.get(ancestor)
            if holder is not None and holder.kind != "dir":
                violations.append(
                    f"member {name!r} is below non-directory {holder.kind} "
                    f"member {ancestor!r}"
                )
                break

    for member in members:
        if member.kind != "hardlink":
            continue
        try:
            target_name = canonical_member(member.linkname)
        except GuardError:
            continue
        target_member = names.get(target_name)
        if target_member is None:
            violations.append(
                f"hardlink target is not present in the archive: "
                f"{member.name} -> {member.linkname}"
            )
        elif target_member.kind != "file":
            violations.append(
                f"hardlink target is not a regular file: "
                f"{member.name} -> {member.linkname}"
            )

    required_missing: list[str] = []
    for pattern in required_members:
        try:
            matched = any(re.search(pattern, name) for name in names)
        except re.error as exc:
            violations.append(f"invalid required pattern {pattern!r}: {exc}")
            continue
        if not matched:
            required_missing.append(pattern)

    for expected in required_files:
        try:
            name = canonical_member(expected.lstrip("/"))
        except GuardError as exc:
            violations.append(f"invalid required file {expected!r}: {exc}")
            continue
        holder = names.get(name)
        if holder is None:
            required_missing.append(expected)
        elif holder.kind != "file":
            violations.append(
                f"required file {expected!r} is a {holder.kind}, not a regular file"
            )

    for expected in required_dirs:
        try:
            name = canonical_member(expected.lstrip("/"))
        except GuardError as exc:
            violations.append(f"invalid required directory {expected!r}: {exc}")
            continue
        holder = names.get(name)
        if holder is None:
            required_missing.append(expected)
        elif holder.kind != "dir":
            violations.append(
                f"required directory {expected!r} is a {holder.kind}, not a directory"
            )

    return _result(
        path,
        len(members),
        violations,
        required_missing,
        actual_sha256,
    )


def _result(
    path: str,
    member_count: int,
    violations: list[str],
    required_missing: list[str],
    actual_sha256: str | None,
) -> dict[str, Any]:
    return {
        "ok": not violations and not required_missing,
        "archive": path,
        "member_count": member_count,
        "violations": violations,
        "required_missing": required_missing,
        "sha256": actual_sha256,
    }


def load_spec(args: argparse.Namespace) -> dict[str, Any]:
    if args.spec_json:
        try:
            raw = base64.b64decode(args.spec_json, validate=True)
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GuardError(f"invalid --spec-json payload: {exc}") from exc
    if args.spec_file:
        try:
            if args.spec_file == "-":
                return json.load(sys.stdin)
            with open(args.spec_file, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise GuardError(f"cannot read specification: {exc}") from exc
    raise GuardError("one of --spec-json or --spec-file is required")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", help="archive path (overrides specification)")
    parser.add_argument("--spec-json", help="base64-encoded JSON specification")
    parser.add_argument("--spec-file", help="JSON specification file, or - for stdin")
    args = parser.parse_args(argv)

    try:
        spec = load_spec(args)
        archive = args.archive or spec.get("archive")
        if not archive:
            raise GuardError("archive path is missing")
        result = validate_archive(
            archive,
            spec.get("allowed_roots", []),
            spec.get("required_members", []),
            spec.get("required_files", []),
            spec.get("required_dirs", []),
            spec.get("forbidden_patterns"),
            spec.get("expected_sha256"),
        )
    except GuardError as exc:
        result = {
            "ok": False,
            "archive": None,
            "member_count": 0,
            "violations": [str(exc)],
            "required_missing": [],
            "sha256": None,
        }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
