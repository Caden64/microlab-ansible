"""Durable advisory lock shared with the Technitium TLS renewal helper.

The renewal helper uses ``fcntl.flock`` on
``/var/lib/technitium-tls/renew.lock``.  Backup and restore must take the
*same* lock for the whole critical section, not one lock per command.  This
module only opens the existing path; it never unlinks, renames, or recreates
the lock file or its directory.  The inode therefore stays stable for the
renewal helper and for manual helper invocations.
"""

from __future__ import annotations

import fcntl
import os
import time
from pathlib import Path


class LockTimeout(Exception):
    """Timed out waiting for the durable recovery lock."""


class DurableLock:
    """Exclusive flock that survives for the lifetime of one helper process.

    The lock is acquired with ``LOCK_EX | LOCK_NB`` in a poll loop so the
    caller can wait for an in-flight renewal to finish.  It is released in
    ``__exit__``; the lock file itself is deliberately left in place.
    """

    def __init__(
        self,
        path: str,
        timeout: float = 300.0,
        poll_interval: float = 0.5,
    ) -> None:
        self.path = path
        self.timeout = max(0.0, float(timeout))
        self.poll_interval = max(0.05, float(poll_interval))
        self.fd: int | None = None
        self.acquired_at: float | None = None

    def __enter__(self) -> "DurableLock":
        if not self.path:
            return self

        # Creating a missing state directory is safe: an existing directory,
        # lock inode, and status file are never replaced.  The renewal service
        # uses StateDirectory=technitium-tls for the same reason.
        Path(self.path).parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise LockTimeout(
                        f"timed out after {self.timeout:g}s waiting for {self.path}"
                    )
                time.sleep(self.poll_interval)

        self.fd = fd
        self.acquired_at = time.time()
        # A pid is diagnostic only.  The helper writes its own pid when it
        # later acquires the same inode, so do not treat this as authoritative.
        try:
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode("ascii"))
        except OSError:
            pass
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is None:
            return
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = None

    @property
    def held_seconds(self) -> float:
        if self.acquired_at is None:
            return 0.0
        return max(0.0, time.time() - self.acquired_at)
