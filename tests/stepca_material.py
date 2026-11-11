"""Shared throwaway CA material helpers for the step_ca tests.

Nothing here contacts a host or a live service. OpenSSL creates a disposable
root and intermediate in a temporary directory so the preflight tests can run
real stat/find/OpenSSL checks instead of feeding pre-classified booleans to the
state filter.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

PASSWORD = "integration-only-ca-password"
OPENSSL = shutil.which("openssl")
TMP_ROOT = (
    Path("/tmp/opencode")
    if Path("/tmp/opencode").is_dir()
    else Path("/tmp")
)


def run_checked(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
        **kwargs,
    )


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_snapshot(paths: list[Path]) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for root in paths:
        if root.is_file():
            snapshot[str(root)] = file_digest(root)
            continue
        for entry in sorted(root.rglob("*")):
            if entry.is_file() and not entry.is_symlink():
                snapshot[str(entry.relative_to(root.parent))] = file_digest(entry)
    return snapshot


@dataclass(frozen=True)
class CaMaterial:
    root_key: Path
    root_cert: Path
    intermediate_key: Path
    intermediate_csr: Path
    intermediate_cert: Path
    password_file: Path
    password: str
    fingerprint_normalized: str


def generate_ca_material(directory: Path, password: str = PASSWORD) -> CaMaterial:
    """Create an encrypted intermediate chained to a throwaway root."""

    if OPENSSL is None:
        raise RuntimeError("openssl is required to generate test CA material")

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    root_key = directory / "root_ca_key"
    root_cert = directory / "root_ca.crt"
    intermediate_key = directory / "intermediate_ca_key"
    intermediate_csr = directory / "intermediate_ca.csr"
    intermediate_cert = directory / "intermediate_ca.crt"
    password_file = directory / "password"
    extensions = directory / "intermediate.ext"
    password_file.write_text(password + "\n")
    extensions.write_text(
        "[v3_ca]\n"
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )

    run_checked(
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(root_key),
            "-out",
            str(root_cert),
            "-days",
            "3650",
            "-sha256",
            "-subj",
            "/CN=Microlab Integration Test Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )
    run_checked(
        [
            OPENSSL,
            "genpkey",
            "-algorithm",
            "RSA",
            "-aes-256-cbc",
            "-pass",
            "pass:" + password,
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(intermediate_key),
        ]
    )
    run_checked(
        [
            OPENSSL,
            "req",
            "-new",
            "-key",
            str(intermediate_key),
            "-passin",
            "pass:" + password,
            "-subj",
            "/CN=Microlab Integration Test Intermediate",
            "-out",
            str(intermediate_csr),
        ]
    )
    run_checked(
        [
            OPENSSL,
            "x509",
            "-req",
            "-in",
            str(intermediate_csr),
            "-CA",
            str(root_cert),
            "-CAkey",
            str(root_key),
            "-CAcreateserial",
            "-out",
            str(intermediate_cert),
            "-days",
            "1825",
            "-sha256",
            "-extfile",
            str(extensions),
            "-extensions",
            "v3_ca",
        ]
    )
    fingerprint = run_checked(
        [
            OPENSSL,
            "x509",
            "-in",
            str(root_cert),
            "-noout",
            "-fingerprint",
            "-sha256",
        ]
    ).stdout
    fingerprint_normalized = (
        fingerprint.split("=", 1)[1].strip().replace(":", "").upper()
    )
    return CaMaterial(
        root_key=root_key,
        root_cert=root_cert,
        intermediate_key=intermediate_key,
        intermediate_csr=intermediate_csr,
        intermediate_cert=intermediate_cert,
        password_file=password_file,
        password=password,
        fingerprint_normalized=fingerprint_normalized,
    )
