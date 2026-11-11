"""Test-only Ansible connection that simulates a filesystem-separated target.

The step_ca preflight validates controller-side source files on the controller
(``delegate_to: localhost``) and target-side material on the target. Testing
that distinction on a single ``connection: local`` host masks the bug because
controller and target share one filesystem.

This connection executes every remote command with ``bwrap`` (bubblewrap) in a
separate mount namespace. The host root is mounted read-only, selected paths are
bound read-write, and controller-only paths can be masked or overlaid with a
different directory. It is repository test infrastructure only; it never
touches a real host service or the network.

Environment (set by the tests through the inventory/subprocess environment):

``STEPCA_SANDBOX_BINDS``
    JSON list of ``[host_path, sandbox_path]`` pairs mounted read-write.
``STEPCA_SANDBOX_MASKS``
    JSON list of sandbox paths replaced by an empty tmpfs, hiding the
    controller's copy from the simulated target.
``STEPCA_SANDBOX_TMPFS``
    JSON list of sandbox paths replaced by a writable tmpfs before bind mounts.
    Used to provide a fake ``/srv`` whose paths do not exist on the controller.
``STEPCA_SANDBOX_DIRS``
    JSON list of sandbox directories to create (inside a tmpfs) so a bind
    destination exists.
``STEPCA_SANDBOX_BWRAP``
    Path to the ``bwrap`` binary (default ``/usr/bin/bwrap``).
``STEPCA_SANDBOX_TMPDIR``
    Writable directory inside the sandbox exported as ``TMPDIR`` and ``HOME``
    so Python's ``tempfile`` and Ansible module scratch files work even though
    the sandbox root is read-only.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess

from ansible.errors import AnsibleError
from ansible.plugins.connection.local import Connection as LocalConnection

DOCUMENTATION = r"""
name: stepca_isolated
short_description: test-only bubblewrap-backed local connection
description:
  - Executes commands in a bubblewrap mount namespace with the host root
    read-only and only declared paths writable.
  - Used by the repository's step_ca tests to simulate a target filesystem
    distinct from the Ansible controller.
  - Never used by the role itself.
options: {}
"""


class Connection(LocalConnection):
    """Run Ansible module commands in a bwrap mount namespace."""

    transport = "stepca_isolated"
    has_pipelining = True

    def _env_list(self, name: str) -> list:
        try:
            value = json.loads(os.environ.get(name, "[]"))
        except ValueError as exc:
            raise AnsibleError(f"invalid {name} for stepca_isolated: {exc}")
        if not isinstance(value, list):
            raise AnsibleError(f"{name} for stepca_isolated must be a JSON list")
        return value

    def _sandbox_argv(self, cmd: str) -> list[str]:
        bwrap = os.environ.get("STEPCA_SANDBOX_BWRAP", "/usr/bin/bwrap")
        if not os.path.exists(bwrap):
            raise AnsibleError(
                "stepca_isolated requires bubblewrap; set STEPCA_SANDBOX_BWRAP "
                "to the bwrap binary"
            )
        argv = [bwrap, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
        tmpdir = os.environ.get("STEPCA_SANDBOX_TMPDIR")
        if tmpdir:
            argv += ["--setenv", "TMPDIR", tmpdir, "--setenv", "HOME", tmpdir]
        for path in self._env_list("STEPCA_SANDBOX_TMPFS"):
            argv += ["--tmpfs", str(path)]
        for path in self._env_list("STEPCA_SANDBOX_DIRS"):
            argv += ["--dir", str(path)]
        for path in self._env_list("STEPCA_SANDBOX_MASKS"):
            argv += ["--tmpfs", str(path)]
        for source, destination in self._env_list("STEPCA_SANDBOX_BINDS"):
            argv += ["--bind", str(source), str(destination)]
        argv += ["--", "/bin/sh", "-c", cmd]
        return argv

    def _run(self, cmd: str, in_data: bytes | None = None) -> tuple[int, bytes, bytes]:
        process = subprocess.Popen(
            self._sandbox_argv(cmd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate(in_data)
        return process.returncode, stdout, stderr

    def exec_command(self, cmd, in_data=None, sudoable=True):
        if isinstance(cmd, bytes):
            cmd = cmd.decode("utf-8", "surrogateescape")
        if not isinstance(cmd, str):
            raise AnsibleError("stepca_isolated only accepts a shell command string")
        return self._run(cmd, in_data)

    # The inherited local put_file copies directly in the host mount namespace,
    # which cannot reach sandbox-only paths such as /srv/stepca-target. Write
    # through the sandbox instead so copy/template-style actions see the same
    # filesystem the modules do.
    def put_file(self, in_path: str, out_path: str) -> None:
        with open(in_path, "rb") as handle:
            data = handle.read()
        rc, _stdout, stderr = self._run(
            f"cat > {shlex.quote(out_path)}", in_data=data
        )
        if rc != 0:
            raise AnsibleError(
                "failed to write into the stepca_isolated sandbox: "
                + stderr.decode("utf-8", "replace")
            )
