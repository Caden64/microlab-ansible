"""Pure state classification for the step_ca role.

The role must never turn a missing ``ca.json`` into an implicit CA
initialisation.  Keeping the decision table in one small, importable function
makes the fail-closed matrix testable without a live host or Ansible.

Two different questions are deliberately answered by two different layers:

* ``tasks/preflight.yml`` answers "is the controller-side source material
  complete and cryptographically valid?" before anything is copied.
* this filter answers "what is the target's durable state, and which explicit
  transition (if any) is allowed?" using only observed target facts.

A first deployment is therefore allowed on a genuinely empty target when the
controller sources are complete.  A partial target still fails closed: mixing a
new source with some pre-existing target material is never treated as a fresh
CA.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Tuple

# The role supports exactly one local database backend.  badgerv2 is a directory
# of Badger v2 files: a MANIFEST plus at least one numbered value-log or sorted
# table.  An arbitrary file (or an empty subdirectory) is not durable CA data.
SUPPORTED_DB_TYPES = frozenset({"badgerv2"})
BADGER_MANIFEST = "MANIFEST"
BADGER_TABLE = re.compile(r"^\d{6}\.(?:vlog|sst)$")


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _entry_path(entry: Mapping[str, Any]) -> str:
    path = entry.get("path")
    if path:
        return str(path)
    return str(entry.get("name", ""))


def _entry_name(entry: Mapping[str, Any]) -> str:
    name = entry.get("name")
    if name:
        return str(name)
    return os.path.basename(_entry_path(entry).rstrip("/"))


def evaluate_badger_database(
    files: Iterable[Mapping[str, Any]], db_type: str = "badgerv2"
) -> Tuple[bool, bool, str]:
    """Return ``(durable, has_entries, reason)`` for a badgerv2 data directory.

    ``files`` is the ``files`` list from ``ansible.builtin.find`` with
    ``file_type: any``.  The check is intentionally structural rather than
    "the directory is non-empty":

    * empty directory -> no durable data, not an error by itself;
    * any entry that is not a regular non-empty non-symlink file (including an
      empty subdirectory) -> invalid;
    * no ``MANIFEST`` or no numbered ``.vlog``/``.sst`` -> invalid.

    Additional regular, non-empty Badger files are allowed.  This avoids
    treating an arbitrary non-empty file as proof of a valid database while
    still accepting normal Badger v2 side files such as ``KEYREGISTRY``.
    """

    normalised: List[Dict[str, Any]] = []
    for entry in files or []:
        normalised.append(
            {
                "path": _entry_path(entry),
                "name": _entry_name(entry),
                "isreg": _truthy(entry.get("isreg", False)),
                "isdir": _truthy(entry.get("isdir", False)),
                "islnk": _truthy(entry.get("islnk", False)),
                "size": int(entry.get("size", 0) or 0),
            }
        )

    if not normalised:
        if db_type not in SUPPORTED_DB_TYPES:
            return (
                False,
                False,
                "database backend %r is not supported; this role only accepts "
                "badgerv2" % (db_type,),
            )
        return False, False, "the database directory is empty"

    if db_type not in SUPPORTED_DB_TYPES:
        return (
            False,
            True,
            "database backend %r is not supported; this role only accepts "
            "badgerv2" % (db_type,),
        )

    bad_entries = [
        entry
        for entry in normalised
        if entry["isdir"]
        or entry["islnk"]
        or not entry["isreg"]
        or entry["size"] <= 0
    ]
    if bad_entries:
        names = ", ".join(sorted(entry["name"] for entry in bad_entries))
        return (
            False,
            True,
            "the database directory contains entries that are not regular "
            "non-empty files (%s)" % names,
        )

    names = {entry["name"] for entry in normalised}
    has_manifest = BADGER_MANIFEST in names
    has_table = any(BADGER_TABLE.match(name) for name in names)
    if not has_manifest:
        return (
            False,
            True,
            "no badgerv2 MANIFEST file was found; an arbitrary non-empty file "
            "does not prove a valid CA database",
        )
    if not has_table:
        return (
            False,
            True,
            "no numbered badgerv2 .vlog or .sst table was found; the database "
            "looks like leftover files rather than durable CA data",
        )
    return True, True, ""


def classify_step_ca_state(state: Mapping[str, Any]) -> Dict[str, Any]:
    """Classify on-host CA state and return the only allowed next action.

    ``state`` keys are the booleans gathered by ``tasks/preflight.yml``:

    * ``config_exists`` / ``config_valid``
    * ``root_exists`` / ``root_valid``, and the same for ``crt``, ``key`` and
      ``password``.  ``*_exists`` means the path exists at all; ``*_valid``
      means it is a regular, non-symlink, non-empty file.  When ``*_valid`` is
      omitted it defaults to ``*_exists`` for direct unit-test callers.
    * ``db_exists``; ``db_files`` (the ``find`` result) and ``db_type``; or the
      legacy ``db_nonempty`` / ``db_valid`` pair.
    * ``initial_deploy`` and ``recover_missing_config``.

    Actions:

    * ``normal`` - complete durable state and ``ca.json`` are present.
    * ``initial-deploy`` - explicit first deployment with valid controller
      sources, no durable database, and a target that is either empty or already
      holds the complete offline material.
    * ``recover-config`` - explicit configuration-only recovery where every
      durable input *including a structurally valid badgerv2 database* is
      present.
    * ``fail`` - anything partial, ambiguous, invalid, or unexpected.  The
      caller must restore the complete tree from backup instead of creating new
      state.
    """

    config_exists = _truthy(state.get("config_exists", False))
    config_valid = _truthy(state.get("config_valid", config_exists))

    def file_state(prefix: str) -> Tuple[bool, bool]:
        exists = _truthy(state.get("%s_exists" % prefix, False))
        valid = _truthy(state.get("%s_valid" % prefix, exists))
        return exists, exists and valid

    root_exists, root_valid = file_state("root")
    crt_exists, crt_valid = file_state("crt")
    key_exists, key_valid = file_state("key")
    password_exists, password_valid = file_state("password")

    db_type = str(state.get("db_type", "badgerv2"))
    db_backend_supported = db_type in SUPPORTED_DB_TYPES
    db_exists = _truthy(state.get("db_exists", False))
    explicit_db_invalid = _truthy(state.get("db_invalid", False))

    if "db_files" in state:
        db_valid, db_has_entries, db_reason = evaluate_badger_database(
            state.get("db_files") or [], db_type
        )
        db_has_data = bool(db_exists and db_valid)
        db_invalid = bool(
            explicit_db_invalid
            or not db_backend_supported
            or (db_has_entries and not db_valid)
        )
    else:
        db_nonempty = _truthy(state.get("db_nonempty", False))
        db_valid = _truthy(state.get("db_valid", db_exists and db_nonempty))
        db_has_data = bool(db_exists and db_valid)
        db_invalid = bool(
            explicit_db_invalid
            or not db_backend_supported
            or (db_exists and db_nonempty and not db_valid)
        )
        db_reason = (
            "database backend %r is not supported; this role only accepts "
            "badgerv2" % (db_type,)
            if not db_backend_supported
            else ("" if db_valid or not db_nonempty else "the database is not valid")
        )

    material_exists = [root_exists, crt_exists, key_exists, password_exists]
    material_valid = [root_valid, crt_valid, key_valid, password_valid]
    material_complete = all(material_valid)
    material_none = not any(material_exists)
    material_invalid = any(
        exists and not valid
        for exists, valid in zip(material_exists, material_valid)
    )
    material_partial = any(material_exists) and not all(material_valid)
    durable_state_complete = bool(material_complete and db_has_data)

    initial_deploy = _truthy(state.get("initial_deploy", False))
    recover_missing_config = _truthy(state.get("recover_missing_config", False))
    source_material_valid = _truthy(state.get("source_material_valid", True))

    if config_exists and not config_valid:
        action = "fail"
        reason = (
            "ca.json exists but is not a regular non-empty file. Do not treat "
            "a truncated, empty, or symlinked configuration as missing and do "
            "not re-initialise the CA. Restore ca.json from a verified backup."
        )
    elif material_invalid:
        action = "fail"
        reason = (
            "one or more durable CA material paths exist but are empty, "
            "symlinks, not regular files, or otherwise invalid. Restore the "
            "complete /etc/step-ca tree from a verified backup; never replace "
            "partial material as part of a new deployment."
        )
    elif db_invalid:
        action = "fail"
        reason = (
            "the CA database directory does not contain a valid %s backend "
            "(%s). Restore the complete /etc/step-ca tree from a verified "
            "backup; an empty directory, empty subdirectory, or arbitrary "
            "file is not a CA database." % (db_type, db_reason)
        )
    elif config_exists:
        if durable_state_complete:
            action = "normal"
            reason = (
                "ca.json and the complete durable CA state are present; "
                "performing a normal redeploy."
            )
        else:
            action = "fail"
            reason = (
                "ca.json is present but the durable CA state is incomplete "
                "(offline material, database directory, or a structurally "
                "valid non-empty database is missing). Restore the complete "
                "/etc/step-ca tree from a verified backup before redeploying. "
                "Do not create a replacement database or regenerate material."
            )
    elif initial_deploy and recover_missing_config:
        action = "fail"
        reason = (
            "microlab_step_ca_initial_deploy and "
            "microlab_step_ca_recover_missing_config are mutually exclusive. "
            "Choose the documented first-deployment or configuration-only "
            "recovery path, or restore the complete /etc/step-ca tree."
        )
    elif recover_missing_config:
        if durable_state_complete:
            action = "recover-config"
            reason = (
                "ca.json is the only missing piece and the complete durable CA "
                "state (offline material plus a structurally valid badgerv2 "
                "database) is present; re-rendering the role-managed "
                "configuration only."
            )
        else:
            action = "fail"
            reason = (
                "configuration-only recovery requires the complete "
                "offline-issued CA material *and* an existing structurally "
                "valid non-empty CA database. A missing database, empty "
                "subdirectory, or invalid material means this is not a "
                "configuration-only recovery: restore the whole /etc/step-ca "
                "tree from backup instead of creating an empty database."
            )
    elif initial_deploy:
        if not source_material_valid:
            action = "fail"
            reason = (
                "explicit first deployment requires complete, valid "
                "controller-side offline material. The controller source "
                "preflight failed before any target write."
            )
        elif db_has_data:
            action = "fail"
            reason = (
                "first deployment requires no existing non-empty CA database. "
                "An existing database without ca.json is not a first "
                "deployment; use configuration-only recovery only when ca.json "
                "alone is missing, otherwise restore the complete tree from "
                "backup."
            )
        elif material_complete or material_none:
            action = "initial-deploy"
            reason = (
                "explicit first deployment: ca.json and the CA database do not "
                "exist, the controller-side material is complete, and the "
                "target is either empty or already holds the complete "
                "offline-issued material."
            )
        else:
            action = "fail"
            reason = (
                "first deployment requires an empty target or the complete "
                "offline-issued CA material, not a partial target. Some but "
                "not all material is present, so this is not a fresh CA; "
                "restore the complete tree from backup."
            )
    else:
        action = "fail"
        reason = (
            "ca.json is missing and no explicit state transition was selected. "
            "This role never runs `step ca init` and never creates an empty "
            "database. Restore the complete /etc/step-ca tree from a verified "
            "backup. Use microlab_step_ca_initial_deploy=true only for a new "
            "deployment with complete offline material and no database, or "
            "microlab_step_ca_recover_missing_config=true only when ca.json "
            "alone is missing and all durable state is present."
        )

    return {
        "action": action,
        "reason": reason,
        "material_complete": material_complete,
        "material_none": material_none,
        "material_invalid": material_invalid,
        "material_partial": material_partial,
        "has_durable_database": db_has_data,
        "database_invalid": db_invalid,
        "durable_state_complete": durable_state_complete,
        "sources_valid": source_material_valid,
    }


class FilterModule:
    def filters(self) -> Dict[str, Any]:
        return {"step_ca_state": classify_step_ca_state}
