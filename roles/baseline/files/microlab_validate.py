#!/usr/bin/env python3
"""Fail-closed validation for MicroLab inventory and host facts.

Reads one JSON document from argv[1]. This is intentionally plain stdlib so it
works on a minimal Debian host and can also be run by local static checks.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
PLACEHOLDER_RE = re.compile(r"REPLACE", re.IGNORECASE)
DEFAULT_MANAGEMENT_GROUP = "micolab_management"
DEFAULT_CHALLENGE_GROUP = "microlab_challenge"
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]+$")

errors: list[str] = []


def fail(message: str) -> None:
    errors.append(message)


def text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(f"{label} must be a non-empty string")
        return ""
    if PLACEHOLDER_RE.search(value):
        fail(f"{label} still contains a REPLACE_ placeholder")
    return value.strip()


def positive_int(value: object, label: str) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{label} must be a positive integer")
        return None
    return value


def network(value: str, label: str, version: int, allow_zero: bool = False) -> ipaddress._BaseNetwork | None:
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        fail(f"{label} is not a valid CIDR: {value!r} ({exc})")
        return None
    if net.version != version:
        fail(f"{label} must be IPv{version}: {value!r}")
    if not allow_zero and net.prefixlen == 0:
        fail(f"{label} must not be a default route: {value!r}")
    return net


def address(value: str, label: str, version: int) -> ipaddress._BaseAddress | None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        fail(f"{label} is not a valid IP address: {value!r} ({exc})")
        return None
    if addr.version != version:
        fail(f"{label} must be IPv{version}: {value!r}")
    return addr


def path_value(value: object, label: str) -> Path | None:
    raw = text(value, label)
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        fail(f"{label} must be an absolute path: {raw!r}")
    return path


def ipv4_endpoint(value: object, label: str) -> tuple[str, int] | None:
    raw = text(value, label)
    if not raw:
        return None
    host, separator, port_text = raw.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        fail(f"{label} must be an IPv4:port endpoint: {raw!r}")
        return None
    if not re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", host):
        fail(f"{label} must use an IPv4 literal, not a hostname: {raw!r}")
        return None
    address(host, label, 4)
    port = int(port_text)
    if not 1 <= port <= 65535:
        fail(f"{label} port must be from 1 to 65535: {raw!r}")
        return None
    return host, port


def overlap(a: Path, b: Path, label_a: str, label_b: str) -> None:
    if a == b:
        fail(f"{label_a} and {label_b} must not be the same path")
    elif a.is_relative_to(b) or b.is_relative_to(a):
        fail(f"{label_a} and {label_b} must not overlap")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: microlab_validate.py INPUT.json", file=sys.stderr)
        return 2

    try:
        if sys.argv[1] == "-":
            data = json.loads(sys.stdin.read())
        else:
            data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"unable to read validation input: {exc}", file=sys.stderr)
        return 2

    # --- host placement -----------------------------------------------------
    groups = data.get("groups") or []
    management_group = data.get("management_group", DEFAULT_MANAGEMENT_GROUP)
    challenge_group = data.get("challenge_group", DEFAULT_CHALLENGE_GROUP)
    if management_group not in groups:
        fail(f"host must be a member of {management_group!r}")
    if challenge_group in groups:
        fail(f"management host must not be a member of {challenge_group!r}")

    ansible_host = text(data.get("ansible_host"), "ansible_host")
    ssh_addr = address(ansible_host, "ansible_host", 4) if ansible_host else None
    if ansible_host and ssh_addr is None:
        fail("inventory SSH target (ansible_host) must be an IPv4 literal, not a hostname")

    # --- operating system ---------------------------------------------------
    expected_os = text(data.get("expected_os"), "micolab_expected_os")
    os_family = text(data.get("os_family"), "gathered distribution")
    if expected_os and os_family and expected_os.lower() != os_family.lower():
        fail(f"expected {expected_os}, found {os_family}")
    if os_family and os_family.lower() != "debian":
        fail("only Debian is supported by this deployment")

    os_major = str(data.get("os_major", ""))
    supported = [str(v) for v in (data.get("supported_majors") or [])]
    if not supported:
        fail("micolab_supported_debian_majors must not be empty")
    elif os_major not in supported:
        fail(f"Debian major {os_major!r} is not supported: {supported}")

    arch_map = {"aarch64": "arm64", "x86_64": "amd64"}
    expected_arch = text(data.get("expected_architecture"), "micolab_expected_architecture")
    actual_arch = arch_map.get(str(data.get("ansible_architecture", "")))
    if expected_arch not in ("arm64", "amd64"):
        fail("micolab_expected_architecture must be arm64 or amd64")
    elif actual_arch != expected_arch:
        fail(
            f"architecture mismatch: inventory says {expected_arch}, "
            f"host reports {data.get('ansible_architecture')!r} ({actual_arch})"
        )

    # --- paths and storage --------------------------------------------------
    paths: dict[str, Path] = {}
    for key, label in (
        ("install", "micolab_technitium_install_dir"),
        ("config", "micolab_technitium_config_dir"),
        ("logs", "micolab_technitium_log_dir"),
        ("dotnet", "micolab_dotnet_install_dir"),
    ):
        path = path_value((data.get("paths") or {}).get(key), label)
        if path:
            paths[key] = path
    if len(paths) == 4:
        overlap(paths["config"], paths["logs"], "config dir", "log dir")
        overlap(paths["install"], paths["config"], "install dir", "config dir")
        overlap(paths["install"], paths["logs"], "install dir", "log dir")
        overlap(paths["install"], paths["dotnet"], "install dir", "dotnet dir")
        overlap(paths["config"], paths["dotnet"], "config dir", "dotnet dir")
        overlap(paths["logs"], paths["dotnet"], "log dir", "dotnet dir")

    min_free = positive_int(data.get("min_free_bytes"), "micolab_min_free_bytes")
    storage_path = path_value(data.get("storage_path"), "micolab_required_storage_path")
    if storage_path and min_free:
        best = None
        for mount in data.get("mounts") or []:
            mount_point = Path(str(mount.get("mount", "")))
            if storage_path.is_relative_to(mount_point):
                if best is None or len(str(mount_point)) > len(str(best.get("mount", ""))):
                    best = mount
        if best is None:
            fail(f"no mounted filesystem contains {storage_path}")
        else:
            available = int(best.get("size_available", 0) or 0)
            if available < min_free:
                fail(
                    f"{storage_path} has {available} bytes free, "
                    f"below required {min_free}"
                )
            if str(best.get("fstype", "")).lower() in ("tmpfs", "ramfs", "devtmpfs"):
                fail(f"{storage_path} is on volatile filesystem {best.get('fstype')}")

    # --- networks -----------------------------------------------------------
    admin_nets = []
    for index, cidr in enumerate(data.get("admin_cidrs") or []):
        net = network(str(cidr), f"micolab_admin_cidrs[{index}]", 4)
        if net:
            admin_nets.append(net)
    if not admin_nets:
        fail("micolab_admin_cidrs must contain at least one IPv4 network")

    client_nets = []
    for index, cidr in enumerate(data.get("client_cidrs") or []):
        net = network(str(cidr), f"micolab_client_cidrs[{index}]", 4)
        if net:
            client_nets.append(net)
    if not client_nets:
        fail("micolab_client_cidrs must contain at least one IPv4 network")

    admin_nets6 = []
    client_nets6 = []
    for label, key, target in (
        ("micolab_admin_cidrs_v6", "admin_cidrs_v6", admin_nets6),
        ("micolab_client_cidrs_v6", "client_cidrs_v6", client_nets6),
    ):
        for index, cidr in enumerate(data.get(key) or []):
            net = network(str(cidr), f"{label}[{index}]", 6)
            if net:
                target.append(net)

    recursion_nets = []
    for index, cidr in enumerate(data.get("recursion_allow_cidrs") or []):
        net = network(str(cidr), f"micolab_dns_recursion_allow_cidrs[{index}]", 4)
        if net:
            recursion_nets.append(net)

    # Networks that the firewall admits for authoritative DNS but that must
    # never enter the recursion ACL.  They have to be distinct from every
    # recursion-allowed network or the "denied" probe class is meaningless.
    authoritative_nets = []
    for index, cidr in enumerate(data.get("authoritative_only_cidrs") or []):
        net = network(str(cidr), f"micolab_dns_authoritative_only_cidrs[{index}]", 4)
        if net:
            authoritative_nets.append(net)
    for index, cidr in enumerate(data.get("authoritative_only_cidrs_v6") or []):
        net = network(str(cidr), f"micolab_dns_authoritative_only_cidrs_v6[{index}]", 6)
        if net:
            authoritative_nets.append(net)
    if data.get("authoritative_only_cidrs_v6") and not data.get("dns_ipv6_enabled"):
        fail("micolab_dns_authoritative_only_cidrs_v6 must be empty when IPv6 is disabled")
    for net in authoritative_nets:
        for other in admin_nets + client_nets + admin_nets6 + client_nets6 + recursion_nets:
            if net.version == other.version and net.overlaps(other):
                fail(
                    "micolab_dns_authoritative_only_cidrs must not overlap "
                    f"admin/client/recursion-allow networks: {net} overlaps {other}"
                )

    # --- DNS naming ---------------------------------------------------------
    domain = text(data.get("domain"), "micolab_domain").lower().rstrip(".")
    zone = text(data.get("dns_zone"), "micolab_dns_zone").lower().rstrip(".")
    primary_ns = text(data.get("primary_ns"), "micolab_dns_primary_ns").lower().rstrip(".")
    if domain and (domain != domain.lower() or domain.endswith(".")):
        fail("micolab_domain must be lowercase without a trailing dot")
    if zone and (zone != zone.lower() or zone.endswith(".")):
        fail("micolab_dns_zone must be lowercase without a trailing dot")
    if primary_ns and (primary_ns != primary_ns.lower() or primary_ns.endswith(".")):
        fail("micolab_dns_primary_ns must be lowercase without a trailing dot")
    if domain and zone and not (domain == zone or domain.endswith("." + zone)):
        fail(f"micolab_domain {domain!r} is not inside zone {zone!r}")
    if domain and primary_ns and not primary_ns.endswith("." + domain):
        fail(f"micolab_dns_primary_ns {primary_ns!r} is not inside {domain!r}")
    if primary_ns and not primary_ns.startswith("ns1."):
        fail("micolab_dns_primary_ns must be ns1.<domain>")

    email = text(data.get("admin_email"), "micolab_dns_admin_email")
    if email and "@" not in email:
        fail("micolab_dns_admin_email must contain @")

    addresses = data.get("dns_addresses") or {}
    required_keys = ("ns1", "ca", "dns", "git")
    if not isinstance(addresses, dict):
        fail("micolab_dns_addresses must be a mapping")
        addresses = {}
    for key in required_keys:
        value = addresses.get(key)
        if value is None:
            fail(f"micolab_dns_addresses.{key} is required")
            continue
        address(str(value), f"micolab_dns_addresses.{key}", 4)

    # --- cold-start recursion fixture --------------------------------------
    fixture_endpoint = ipv4_endpoint(
        data.get("dns_fixture_upstream"), "micolab_dns_fixture_upstream"
    )
    fixture_zone = (
        text(data.get("dns_fixture_zone"), "micolab_dns_fixture_zone")
        .lower()
        .rstrip(".")
    )
    fixture_name = (
        text(data.get("dns_fixture_name"), "micolab_dns_fixture_name")
        .lower()
        .rstrip(".")
    )
    fixture_answer = text(
        data.get("dns_fixture_expected_ip"), "micolab_dns_fixture_expected_ip"
    )
    if fixture_answer:
        address(fixture_answer, "micolab_dns_fixture_expected_ip", 4)
    if fixture_zone and not HOSTNAME_RE.match(fixture_zone):
        fail(f"micolab_dns_fixture_zone is not a valid zone name: {fixture_zone!r}")
    if fixture_zone and domain and (
        fixture_zone == domain or fixture_zone.endswith("." + domain)
    ):
        fail(
            "micolab_dns_fixture_zone must be distinct from and outside "
            f"micolab_domain {domain!r}: {fixture_zone!r}"
        )
    if fixture_zone and zone and fixture_zone == zone:
        fail("micolab_dns_fixture_zone must not be the authoritative hnh zone")
    if fixture_name and not HOSTNAME_RE.match(fixture_name):
        fail(f"micolab_dns_fixture_name is not a valid hostname: {fixture_name!r}")
    if fixture_zone and fixture_name and not (
        fixture_name == fixture_zone or fixture_name.endswith("." + fixture_zone)
    ):
        fail(
            f"micolab_dns_fixture_name {fixture_name!r} is not inside "
            f"micolab_dns_fixture_zone {fixture_zone!r}"
        )
    manage_fixture = data.get("dns_fixture_manage_service")
    if not isinstance(manage_fixture, bool):
        fail("micolab_dns_fixture_manage_service must be a boolean")
    elif manage_fixture and fixture_endpoint:
        listen_host, listen_port = ipv4_endpoint(
            data.get("dns_fixture_listen_endpoint"),
            "micolab_dns_fixture_listen_endpoint",
        ) or ("", 0)
        if fixture_endpoint != (listen_host, listen_port):
            fail(
                "micolab_dns_fixture_upstream must exactly match the managed "
                f"fixture listener {listen_host}:{listen_port}"
            )

    ipv6_enabled = data.get("dns_ipv6_enabled")
    if not isinstance(ipv6_enabled, bool):
        fail("micolab_dns_ipv6_enabled must be a boolean")
        ipv6_enabled = False
    ipv6_addresses = data.get("dns_ipv6_addresses") or {}
    if not isinstance(ipv6_addresses, dict):
        fail("micolab_dns_ipv6_addresses must be a mapping")
        ipv6_addresses = {}
    if ipv6_enabled:
        for key in required_keys:
            value = ipv6_addresses.get(key)
            if value is None:
                fail(f"IPv6 is enabled but micolab_dns_ipv6_addresses.{key} is missing")
            else:
                address(str(value), f"micolab_dns_ipv6_addresses.{key}", 6)
    elif ipv6_addresses:
        fail("micolab_dns_ipv6_addresses must be empty when IPv6 is disabled")

    for index, record in enumerate(data.get("extra_records") or []):
        if not isinstance(record, dict):
            fail(f"micolab_dns_extra_records[{index}] must be a mapping")
            continue
        name = text(record.get("name"), f"extra_records[{index}].name").lower().rstrip(".")
        rtype = str(record.get("type", "")).upper()
        if name and domain and not (name == domain or name.endswith("." + domain)):
            fail(f"extra record {name!r} is outside {domain!r}")
        if rtype not in ("A", "AAAA"):
            fail(f"extra_records[{index}].type must be A or AAAA")
        if rtype == "AAAA" and not ipv6_enabled:
            fail(f"extra_records[{index}] is AAAA but IPv6 is disabled")
        if rtype == "A":
            address(str(record.get("value", "")), f"extra_records[{index}].value", 4)
        if rtype == "AAAA":
            address(str(record.get("value", "")), f"extra_records[{index}].value", 6)

    forwarders = data.get("forwarders") or []
    allow_online = data.get("allow_online_forwarders")
    if not isinstance(allow_online, bool):
        fail("micolab_dns_allow_online_forwarders must be a boolean")
    if forwarders and allow_online is not True:
        fail("online forwarders are configured but micolab_dns_allow_online_forwarders is false")
    for index, forwarder in enumerate(forwarders):
        text(forwarder, f"micolab_dns_forwarders[{index}]")

    # --- ports --------------------------------------------------------------
    ports = {}
    for key, label in (
        ("ssh_port", "micolab_ssh_port"),
        ("dns_port", "micolab_technitium_dns_port"),
        ("admin_port", "micolab_technitium_admin_port"),
        ("dot_port", "micolab_dns_dot_port"),
        ("doh_port", "micolab_dns_doh_port"),
        ("doq_port", "micolab_dns_doq_port"),
    ):
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            fail(f"{label} must be an integer from 1 to 65535")
        else:
            ports[key] = value
    if len(ports) == 6:
        if ports["dns_port"] != 53:
            fail("micolab_technitium_dns_port must be 53 for plain DNS")
        if ports["admin_port"] != 5380:
            fail("micolab_technitium_admin_port must be 5380")
        if ports["dot_port"] != 853:
            fail("micolab_dns_dot_port must be 853")
        if ports["doh_port"] != 8053:
            fail("micolab_dns_doh_port must be 8053 (loopback DoH upstream)")
        if ports["dns_port"] == ports["admin_port"]:
            fail("DNS and admin web ports must differ")
        if ports["ssh_port"] == ports["admin_port"]:
            fail("SSH and admin web ports must differ")
        if ports["ssh_port"] == ports["dns_port"]:
            fail("SSH and DNS ports must differ")

    # --- trust and lifecycle inputs ----------------------------------------
    targets = data.get("trust_targets") or []
    if not targets:
        fail("micolab_trust_targets must not be empty")
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            fail(f"micolab_trust_targets[{index}] must be a mapping")
            continue
        name = text(target.get("name"), f"micolab_trust_targets[{index}].name").lower().rstrip(".")
        role = text(target.get("role"), f"micolab_trust_targets[{index}].role")
        if name and not HOSTNAME_RE.match(name):
            fail(f"trust target name is not a valid hostname: {name!r}")
        if name and domain and not (name == domain or name.endswith("." + domain)):
            fail(f"trust target {name!r} is outside {domain!r}")
        if role and PLACEHOLDER_RE.search(role):
            fail(f"trust target {name!r} role is a placeholder")

    positive_int(
        data.get("max_powered_off_interval_seconds"),
        "micolab_max_powered_off_interval_seconds",
    )

    for key, label in (
        ("log_retention_days", "micolab_dns_log_retention_days"),
        ("stats_retention_days", "micolab_dns_stats_retention_days"),
    ):
        value = data.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3650:
            fail(f"{label} must be an integer from 1 to 3650 (0 would disable cleanup)")
    if not isinstance(data.get("log_queries"), bool):
        fail("micolab_dns_log_queries must be a boolean")

    verify_repo = text(data.get("verify_git_repo"), "micolab_verify_git_repo")
    if verify_repo and (re.search(r"\s", verify_repo) or verify_repo.count("/") != 1):
        fail("micolab_verify_git_repo must be a real owner/repo path with no spaces")

    # --- packages -----------------------------------------------------------
    packages = data.get("required_packages") or []
    if not packages:
        fail("micolab_required_packages must not be empty")
    installed = [str(p) for p in data.get("installed_packages") or []]
    for package in packages:
        name = text(package, "micolab_required_packages entry")
        if name and not PACKAGE_RE.match(name):
            fail(f"invalid package name in micolab_required_packages: {name!r}")
        if name and name not in installed:
            fail(f"required package is not installed: {name}")

    for prefix in data.get("required_package_prefixes") or []:
        prefix = text(prefix, "micolab_required_package_prefixes entry")
        if prefix and not any(package.startswith(prefix) for package in installed):
            fail(f"no installed package provides required prefix: {prefix}")

    # --- offline artifacts --------------------------------------------------
    artifacts = data.get("staged_artifacts") or []
    if not isinstance(artifacts, list):
        fail("micolab_staged_artifacts must be a list")
        artifacts = []
    names = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            fail(f"micolab_staged_artifacts[{index}] must be a mapping")
            continue
        name = text(artifact.get("name"), f"staged_artifacts[{index}].name")
        version = text(artifact.get("version"), f"staged_artifacts[{index}].version")
        path = path_value(artifact.get("path"), f"staged_artifacts[{index}].path")
        digest = text(artifact.get("sha256"), f"staged_artifacts[{index}].sha256")
        if name:
            if name in names:
                fail(f"duplicate staged artifact name: {name}")
            names.add(name)
        if version and not re.match(r"^v?[0-9]+(?:\.[0-9A-Za-z]+)+", version):
            fail(f"artifact {name!r} version is not pinned: {version!r}")
        if digest and not SHA256_RE.match(digest):
            fail(f"artifact {name!r} sha256 must be 64 hex characters")

    if "technitium" not in names:
        fail("micolab_staged_artifacts must contain an artifact named 'technitium'")
    if "dotnet-aspnetcore-runtime" not in names:
        fail("micolab_staged_artifacts must contain 'dotnet-aspnetcore-runtime'")

    technitium_version = text(
        data.get("technitium_version"), "micolab_technitium_version"
    )
    tech_artifact = next(
        (a for a in artifacts if isinstance(a, dict) and a.get("name") == "technitium"),
        None,
    )
    if tech_artifact and technitium_version:
        if str(tech_artifact.get("version")) != technitium_version:
            fail(
                "micolab_technitium_version does not match the pinned "
                f"technitium artifact version ({tech_artifact.get('version')!r})"
            )
    runtime_artifact = next(
        (
            a
            for a in artifacts
            if isinstance(a, dict) and a.get("name") == "dotnet-aspnetcore-runtime"
        ),
        None,
    )
    runtime_major = text(
        data.get("runtime_major"), "micolab_technitium_runtime_major"
    )
    if runtime_artifact and runtime_major:
        if not str(runtime_artifact.get("version", "")).startswith(runtime_major + "."):
            fail(
                "dotnet-aspnetcore-runtime version must start with "
                f"{runtime_major}."
            )

    # --- package/port conflict pre-check ------------------------------------
    ss_output = data.get("ss_output") or ""
    allowed_processes = {
        53: ("dns-server", "technitium", "dotnet", "DnsServerApp"),
        5380: ("dns-server", "technitium", "dotnet", "DnsServerApp"),
        80: ("caddy",),
        443: ("caddy",),
        853: ("dns-server", "technitium", "dotnet", "DnsServerApp"),
    }
    for line in str(ss_output).splitlines():
        if not line.strip():
            continue
        match = re.search(r":(\d+)\s+\S+\s+", line)
        if not match:
            continue
        port = int(match.group(1))
        if port not in allowed_processes and port != ports.get("ssh_port"):
            continue
        process_match = re.search(r'users:\(\("([^"]+)"', line)
        process = process_match.group(1) if process_match else "unknown"
        if port == ports.get("ssh_port"):
            allowed = ("sshd",)
        else:
            allowed = allowed_processes[port]
        if process == "systemd-resolve":
            fail(
                "systemd-resolved is listening on port 53; disable its stub "
                "resolver before changing the host resolver to Technitium"
            )
        elif not any(process.startswith(name) for name in allowed):
            fail(
                f"unexpected listener on port {port}: process {process!r}; "
                f"allowed: {', '.join(allowed)}"
            )

    if errors:
        print("MicroLab input validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("MicroLab input validation passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
