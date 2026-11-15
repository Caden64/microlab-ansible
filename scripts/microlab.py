#!/usr/bin/env python3
"""Local controller. No command contacts inventory hosts except deploy/verify.

Contracts: artifacts delegates --inventory PATH --directory PATH to the sibling
microlab_artifacts.py; deploy --stage bootstrap/services selects bootstrap.yml/
deploy.yml; verify selects verify.yml. No local marker implies acceptance.
"""
import argparse
import copy
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
MANAGEMENT = "microlab_management"
CHALLENGE = "microlab_challenge"
SECRET_KEYS = (
    "micolab_technitium_admin_password", "micolab_technitium_tls_cert_password",
    "micolab_forgejo_secret_key", "micolab_forgejo_internal_token",
    "micolab_forgejo_jwt_secret", "micolab_forgejo_lfs_jwt_secret",
    "micolab_forgejo_admin_password",
)
CA_PATHS = ("microlab_step_ca_root_cert_src", "microlab_step_ca_intermediate_cert_src",
            "microlab_step_ca_intermediate_key_src")
CA_VALUES = ("microlab_step_ca_root_fingerprint_sha256",
             "microlab_step_ca_intermediate_key_password",
             "microlab_step_ca_technitium_jwk_key",
             "microlab_step_ca_technitium_jwk_encrypted_key")
TOKENS = ("micolab_technitium_api_token", "micolab_technitium_enrollment_token")


class Checkpoint(Exception):
    """Safe operator-facing diagnostic; never includes external tool output."""


class OpaqueVault(str):
    pass


def parse_yaml(text):
    if yaml is None:
        raise Checkpoint("Install controller dependencies: python3 -m pip install ansible-core PyYAML")
    class Loader(yaml.SafeLoader):
        pass
    def mapping(loader, node):
        loader.flatten_mapping(node)
        result = {}
        for keynode, valnode in node.value:
            key = loader.construct_object(keynode)
            if key in result:
                raise ValueError()
            result[key] = loader.construct_object(valnode)
        return result
    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    Loader.add_constructor("!vault", lambda loader, node: OpaqueVault(loader.construct_scalar(node)))
    try:
        value = yaml.load(text, Loader=Loader)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (yaml.YAMLError, ValueError):
        raise Checkpoint("Invalid YAML mapping. Review the local file privately; its contents were not logged.") from None


def need_tool(name):
    if not shutil.which(name):
        raise Checkpoint("Missing %s. Install: python3 -m pip install ansible-core PyYAML; ansible-galaxy collection install -r requirements.yml" % name)


class Vault:
    """Only ciphertext is durable. Password input is protected, never argv/logs."""
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="microlab-vault-")
        self.password_file = None
        return self

    def credentials(self):
        if os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE") or os.environ.get("ANSIBLE_VAULT_IDENTITY_LIST"):
            return []
        if self.password_file is None:
            if not sys.stdin.isatty():
                raise Checkpoint("Vault needs a terminal for protected input, or ANSIBLE_VAULT_PASSWORD_FILE.")
            password = getpass.getpass("Ansible Vault password (existing password when importing): ")
            if not password or password != getpass.getpass("Confirm Vault password: "):
                raise Checkpoint("Vault passwords must be nonempty and match.")
            self.password_file = Path(self.temp.name) / "password"
            exclusive_write(self.password_file, (password + "\n").encode())
        return ["--vault-password-file", str(self.password_file)]

    def read(self, path):
        need_tool("ansible-vault")
        result = subprocess.run(["ansible-vault", "view", *self.credentials(), str(path)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
        if result.returncode:
            raise Checkpoint("Cannot unlock existing Vault. Nothing was replaced. Check Vault credentials/identity locally.")
        return parse_yaml(result.stdout.decode())

    def encrypt(self, values, destination):
        need_tool("ansible-vault")
        output = Path(self.temp.name) / "encrypted"
        result = subprocess.run(["ansible-vault", "encrypt", *self.credentials(), "--output", str(output)],
                                input=yaml.safe_dump(values).encode(), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=ROOT)
        if result.returncode or not output.is_file() or not output.read_bytes().startswith(b"$ANSIBLE_VAULT;"):
            raise Checkpoint("Vault encryption failed; no plaintext secrets were saved. Check Vault credentials locally.")
        exclusive_write(destination, output.read_bytes())

    def __exit__(self, *args):
        self.temp.cleanup()


def exclusive_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def read_mapping(path, vault=None):
    text = path.read_text()
    if text.startswith("$ANSIBLE_VAULT;"):
        if vault is None:
            raise Checkpoint("Encrypted configuration needs protected inspection; run setup or deploy with Vault credentials.")
        return vault.read(path)
    return parse_yaml(text)


def group_hosts(inventory, group):
    result = {}
    def visit(node, active=False):
        if not isinstance(node, dict):
            raise Checkpoint("Inventory groups must be YAML mappings.")
        hosts = node.get("hosts", {}) or {}
        children = node.get("children", {}) or {}
        if not isinstance(hosts, dict) or not isinstance(children, dict):
            raise Checkpoint("Inventory hosts and children must be YAML mappings.")
        if active:
            result.update({key: value or {} for key, value in hosts.items()})
        for name, child in children.items():
            visit(child or {}, active or name == group)
    visit(inventory.get("all", {}))
    return result


def ip(value):
    try:
        address = ipaddress.IPv4Address(value)
        if address.is_unspecified or address.is_multicast or address.is_loopback:
            raise ValueError()
        return str(address)
    except (ValueError, TypeError, ipaddress.AddressValueError):
        raise Checkpoint("Enter a usable IPv4 literal for each host; DNS is not required for bootstrap.") from None


def cidrs(value, admin=False):
    values = value.replace(",", " ").split() if isinstance(value, str) else value
    if not isinstance(values, list) or not values:
        raise Checkpoint("Provide at least one explicit CIDR; admin workstation /32 or protected VPN is required.")
    try:
        nets = [ipaddress.ip_network(item, strict=True) for item in values]
        if any(net.prefixlen == 0 or net.is_multicast or net.is_loopback for net in nets):
            raise ValueError()
    except (ValueError, TypeError):
        raise Checkpoint("Invalid CIDR. Use canonical networks; never a default route. Admin access needs a specific trusted source.") from None
    return [str(net) for net in nets]


def architecture(value):
    aliases = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}
    if value not in aliases:
        raise Checkpoint("Specify the infra target architecture: arm64 (aarch64) or amd64 (x86_64). It is never inferred from this controller.")
    return aliases[value]


def present(value):
    if isinstance(value, (list, dict)):
        items = value.values() if isinstance(value, dict) else value
        return bool(value) and all(present(item) for item in items)
    return value is not None and value != "" and value != [] and value != {} and not (
        isinstance(value, str) and "REPLACE" in value.upper())


def topology(inventory):
    infra, challenge = group_hosts(inventory, MANAGEMENT), group_hosts(inventory, CHALLENGE)
    if len(infra) != 1 or len(challenge) != 1:
        raise Checkpoint("Define exactly one infra host in microlab_management and one rCTF/microVM host in microlab_challenge. All four infra services share the infra host.")
    name, host = next(iter(infra.items()))
    other, otherhost = next(iter(challenge.items()))
    if not isinstance(host, dict) or not isinstance(otherhost, dict):
        raise Checkpoint("Host variables must be mappings.")
    if name == other or ip(host.get("ansible_host", name)) == ip(otherhost.get("ansible_host", other)):
        raise Checkpoint("Infra and rCTF must be different hosts, even when aliases differ. rCTF is never a deployment target.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise Checkpoint("Use a simple infra inventory alias (letters, digits, dots, underscores, hyphens).")
    if name in ("localhost", "all", "ungrouped") or other in ("localhost", "all", "ungrouped"):
        raise Checkpoint("Use distinct non-reserved host aliases; localhost is reserved for controller validation.")
    return name, host


def local_vars(inventory_path, inventory, name, vault=None, skipped=None):
    """Conservative import; Ansible itself resolves runtime precedence on deploy.

    With a `skipped` list and no Vault, encrypted files are recorded there and
    left unopened (status must stay useful after setup encrypts its secrets).
    """
    def load(path):
        if vault is None and skipped is not None and path.read_text().startswith("$ANSIBLE_VAULT;"):
            skipped.append(path)
            return {}
        return read_mapping(path, vault)
    values = {}
    groups = []
    host_values = {}
    def visit(group, node, depth):
        nonlocal host_values
        if not isinstance(node, dict):
            raise Checkpoint("Inventory groups must be mappings.")
        hosts = node.get("hosts", {}) or {}
        contains = name in hosts
        if contains:
            entry = hosts[name] or {}
            if not isinstance(entry, dict):
                raise Checkpoint("Host variables must be mappings.")
            host_values.update(entry)
        for child, childnode in (node.get("children", {}) or {}).items():
            contains = visit(child, childnode or {}, depth + 1) or contains
        if contains:
            groups.append((depth, group, node.get("vars", {}) or {}))
        return contains
    visit("all", inventory.get("all", {}), 0)
    def files_for(kind, item):
        base = inventory_path.parent / kind / item
        if base.is_dir():
            return sorted(p for p in base.rglob("*") if p.is_file() and not any(part.startswith(".") for part in p.relative_to(base).parts) and p.suffix in ("", ".yml", ".yaml", ".json"))
        return [base, Path(str(base) + ".yml"), Path(str(base) + ".yaml")]
    # Read every applicable group so inherited Vaults cannot trigger rotation.
    for _, group, inline in sorted(groups):
        values.update(inline)
        for path in files_for("group_vars", group):
            if path.is_file():
                values.update(load(path))
    values.update(host_values)
    for path in files_for("host_vars", name):
        if path.is_file():
            values.update(load(path))
    return values


def ask(label, current=None):
    if present(current):
        return current
    if not sys.stdin.isatty():
        raise Checkpoint("Missing %s. Run setup in a terminal or provide its setup option." % label)
    return input(label + ": ").strip()


def new_sidecar(directory, stem):
    path = directory / (stem + ".yml")
    index = 2
    while path.exists():
        path = directory / (stem + "-%d.yml" % index)
        index += 1
    return path


def vars_sidecar(directory, stem):
    """Missing values must win over earlier placeholder entries, never real values."""
    path = new_sidecar(directory, stem)
    existing = sorted(p.name for p in directory.iterdir() if p.is_file()) if directory.is_dir() else []
    if existing and existing[-1] >= path.name:
        path = new_sidecar(directory, existing[-1] + "." + stem)
    return path


def output_vars_directory(path, name):
    # Ansible picks a directory before a same-name .yml file. Never hide a
    # user's flat group_vars file by creating a competing directory.
    host = path.parent / "host_vars" / name
    if any(candidate.is_file() for candidate in (host, Path(str(host) + ".yml"), Path(str(host) + ".yaml"))):
        raise Checkpoint("Existing flat host_vars file needs a protected manual merge; setup will not hide or rewrite it. Use ansible-vault edit for encrypted values.")
    group = path.parent / "group_vars" / MANAGEMENT
    if host.is_dir() or any(candidate.is_file() for candidate in (group, Path(str(group) + ".yml"), Path(str(group) + ".yaml"))):
        return host
    return group


def setup(args):
    path = args.inventory
    with Vault() as vault:
        existing = path.exists()
        inventory = read_mapping(path, vault) if existing else {"all": {"children": {}}}
        infra, challenge = group_hosts(inventory, MANAGEMENT), group_hosts(inventory, CHALLENGE)
        if len(infra) > 1 or len(challenge) > 1:
            raise Checkpoint("Setup expects one host per service group. Review existing topology privately; no files changed.")
        infra_name = next(iter(infra), "microlab-infra")
        challenge_name = next(iter(challenge), "microlab-rctf")
        values = local_vars(path, inventory, infra_name, vault)
        original = copy.deepcopy(inventory)
        def choose(current, supplied):
            return current if present(current) else supplied
        # Host fields are filled only when absent. Supplied flags never replace user values.
        host = dict(infra.get(infra_name, {}))
        host["ansible_host"] = ip(ask("infra IPv4", choose(host.get("ansible_host"), args.infra_ip)))
        host["ansible_user"] = ask("infra SSH user", choose(host.get("ansible_user"), args.ssh_user))
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]*", host["ansible_user"]):
            raise Checkpoint("Invalid SSH user; use the target account name.")
        key = ask("infra SSH private key path", choose(host.get("ansible_ssh_private_key_file"), args.ssh_key))
        if not isinstance(key, str) or "\n" in key or "\x00" in key:
            raise Checkpoint("Invalid SSH key path.")
        host["ansible_ssh_private_key_file"] = str(Path(key).expanduser())
        second = dict(challenge.get(challenge_name, {}))
        second["ansible_host"] = ip(ask("rCTF/microVM IPv4 (recorded only; never deployed)", choose(second.get("ansible_host"), args.rctf_ip)))
        children = inventory.setdefault("all", {}).setdefault("children", {})
        children.setdefault(MANAGEMENT, {}).setdefault("hosts", {})[infra_name] = host
        children.setdefault(CHALLENGE, {}).setdefault("hosts", {})[challenge_name] = second
        topology(inventory)
        additions = {}
        def missing(key, value):
            if not present(values.get(key)):
                additions[key] = value
        missing("micolab_expected_architecture", architecture(ask("infra architecture (arm64/amd64)", values.get("micolab_expected_architecture") if present(values.get("micolab_expected_architecture")) else args.arch)))
        admin = cidrs(ask("admin workstation /32 or protected VPN CIDRs (space separated)", choose(values.get("micolab_admin_cidrs"), args.admin_cidr)), admin=True)
        clients = cidrs(ask("client CIDRs (space separated)", choose(values.get("micolab_client_cidrs"), args.client_cidr)))
        # A client subnet is not an administrator identity. Specific overlap is fine.
        if any(a == c for a in admin for c in clients if ipaddress.ip_network(c).prefixlen < ipaddress.ip_network(c).max_prefixlen):
            raise Checkpoint("Admin CIDR must identify the workstation or protected VPN, not the whole player subnet.")
        missing("micolab_admin_cidrs", admin)
        missing("micolab_client_cidrs", clients)
        defaults = {
            "micolab_expected_os": "Debian",
            "micolab_dns_addresses": dict.fromkeys(("ns1", "ca", "dns", "git"), host["ansible_host"]),
            "micolab_dns_fixture_upstream": "127.0.0.1:5353",
            "micolab_dns_fixture_zone": "fixture.test",
            "micolab_dns_fixture_name": "answer.fixture.test",
            "micolab_dns_fixture_expected_ip": "192.0.2.53",
            "micolab_dns_fixture_manage_service": True,
            "micolab_trust_targets": [{"name": "ca.microlab.hnh", "role": "step_ca"}, {"name": "git.microlab.hnh", "role": "forgejo"}],
            "micolab_max_powered_off_interval_seconds": 86400,
            "micolab_forgejo_admin_username": "microlab-admin",
            "micolab_forgejo_admin_email": "admin@microlab.hnh",
        }
        for key, value in defaults.items():
            missing(key, value)
        addresses = values.get("micolab_dns_addresses", {})
        if addresses and (not isinstance(addresses, dict) or any(present(addresses.get(k)) and addresses[k] != host["ansible_host"] for k in ("ns1", "ca", "dns", "git"))):
            raise Checkpoint("Existing service addresses differ from the infra IPv4. Review them privately; setup will not replace them.")
        if isinstance(addresses, dict) and any(not present(addresses.get(k)) for k in ("ns1", "ca", "dns", "git")):
            additions["micolab_dns_addresses"] = {**addresses, **{k: host["ansible_host"] for k in ("ns1", "ca", "dns", "git") if not present(addresses.get(k))}}
        generated = {}
        for key in SECRET_KEYS:
            if present(values.get(key)):
                continue
            if present(values.get("vault_" + key)):
                additions[key] = "{{ vault_" + key + " }}"
            else:
                generated[key] = secrets.token_urlsafe(48)
        directory = output_vars_directory(path, infra_name) if generated or additions else path.parent / "group_vars" / MANAGEMENT
        # Review before any durable writes. Never rewrite an encrypted inventory.
        changed = not existing or original != inventory
        if existing and changed:
            if path.read_text().startswith("$ANSIBLE_VAULT;") or "!vault" in path.read_text():
                raise Checkpoint("Protected inventory needs a manual host-field merge with ansible-vault edit. Existing files were not changed.")
            print("Existing inventory needs missing host fields merged. Unknown keys will be retained and an exact private backup kept.")
            if not sys.stdin.isatty() or input("Type MERGE to review/authorize this local inventory update: ") != "MERGE":
                raise Checkpoint("Inventory merge not approved; no files changed.")
        # Encrypt first; failed authentication cannot leave a half-created inventory.
        if generated:
            vault.encrypt(generated, vars_sidecar(directory, "setup-vault"))
        if additions:
            exclusive_write(vars_sidecar(directory, "setup"), yaml.safe_dump(additions, sort_keys=False).encode())
        if changed:
            content = yaml.safe_dump(inventory, sort_keys=False).encode()
            if existing:
                backup = new_sidecar(path.parent, "hosts.pre-setup")
                exclusive_write(backup, path.read_bytes())
                fd, temporary = tempfile.mkstemp(prefix=".hosts-", dir=path.parent)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(content)
                    os.replace(temporary, path)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
            else:
                exclusive_write(path, content)
        (ROOT / "artifacts").mkdir(exist_ok=True, mode=0o700)
        print("Local setup saved. Existing values/secrets retained; new application secrets encrypted independently.")
        print("Next: ./microlab artifacts; prepare offline-issued CA material and protected CA credentials in this inventory.")
        print("No CA was created. Root private key must remain offline. Default powered-off budget is 24h; review against certificate lifetime/renewal policy.")
        print("Then ./microlab deploy establishes bootstrap and reports its credential checkpoint. No host has been contacted.")


def runtime_vars(path):
    need_tool("ansible-inventory")
    command = ["ansible-inventory", "--inventory", str(path), "--list"]
    if not (os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE") or os.environ.get("ANSIBLE_VAULT_IDENTITY_LIST")):
        if not sys.stdin.isatty():
            raise Checkpoint("Vault inspection requires a terminal for protected input, or ANSIBLE_VAULT_PASSWORD_FILE. No playbook ran.")
        command.append("--ask-vault-pass")
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise Checkpoint("Cannot inspect Ansible inventory. Check YAML, Vault credentials and dependencies locally; tool output withheld to protect secrets.")
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise Checkpoint("Ansible inventory returned invalid data; output withheld to protect secrets.") from None


def inspection(args, unlock=False, skipped=None):
    if not args.inventory.is_file():
        raise Checkpoint("Site inventory missing. Run ./microlab setup first (existing inventories can be selected with --inventory).")
    with Vault() as vault:
        inventory = read_mapping(args.inventory, vault if unlock else None)
        name, host = topology(inventory)
        if unlock:
            data = runtime_vars(args.inventory)
            members = data.get(MANAGEMENT, {}).get("hosts", [])
            challengers = data.get(CHALLENGE, {}).get("hosts", [])
            if members != [name] or len(challengers) != 1 or name in challengers:
                raise Checkpoint("Resolved Ansible topology differs from the two-host inventory. Review group inheritance before deployment.")
            values = data.get("_meta", {}).get("hostvars", {}).get(name, {})
            other = data.get("_meta", {}).get("hostvars", {}).get(challengers[0], {})
            if ip(values.get("ansible_host", name)) == ip(other.get("ansible_host", challengers[0])):
                raise Checkpoint("Resolved infra and rCTF addresses overlap; refusing deployment.")
            if ip(values.get("ansible_host", name)) != ip(host.get("ansible_host", name)):
                raise Checkpoint("Resolved infra address differs from hosts.yml; review variable precedence before deployment.")
            if values.get("ansible_connection", "ssh") not in ("ssh", "smart", "paramiko", "ansible.builtin.ssh", "ansible.builtin.paramiko_ssh"):
                raise Checkpoint("Infra deployment requires an SSH connection; local/container connection overrides are refused.")
        else:
            values = local_vars(args.inventory, inventory, name, skipped=skipped)
    return name, values


def readiness(values):
    missing = []
    for key in CA_PATHS:
        value = values.get(key)
        if not isinstance(value, str) or not Path(value).is_absolute() or not Path(value).is_file():
            missing.append(key)
    missing.extend(key for key in CA_VALUES if not present(values.get(key)))
    return missing


def execute_playbook(args):
    need_tool("ansible-playbook")
    name, values = inspection(args, unlock=True)
    architecture(values.get("micolab_expected_architecture"))
    admin = cidrs(values.get("micolab_admin_cidrs"), admin=True)
    clients = cidrs(values.get("micolab_client_cidrs"))
    if any(a == c for a in admin for c in clients if ipaddress.ip_network(c).prefixlen < ipaddress.ip_network(c).max_prefixlen):
        raise Checkpoint("Admin CIDR cannot be the entire player subnet. Supply the actual workstation /32 or protected VPN.")
    missing = readiness(values)
    if missing:
        raise Checkpoint("Offline CA preparation checkpoint BEFORE host mutation. Supply controller files/credentials: " + ", ".join(missing) + ". Use ansible-vault edit for secrets; never stage the root private key. No playbook ran.")
    missing_secrets = [key for key in SECRET_KEYS if not present(values.get(key))]
    if missing_secrets:
        raise Checkpoint("Application credential checkpoint: run setup to generate missing durable secrets privately. No playbook ran.")
    if not values.get("micolab_staged_artifacts"):
        raise Checkpoint("Artifact preparation checkpoint: run ./microlab artifacts. No playbook ran.")
    stage = getattr(args, "stage", None)
    api_ready, enrollment_ready = (present(values.get(key)) for key in TOKENS)
    if args.command == "deploy" and stage != "bootstrap":
        if stage == "services" and not api_ready:
            raise Checkpoint("Persistent Technitium API credential missing. Complete ./microlab deploy --stage bootstrap, then store the API token with ansible-vault edit before --stage services. No playbook ran.")
        if stage is None and api_ready and not enrollment_ready:
            raise Checkpoint("Enrollment checkpoint: no one-use token is stored. For an already-enrolled system, use ./microlab deploy --stage services. For first enrollment, store a fresh token privately, then resume. No target state inferred and no playbook ran.")
    bootstrap = stage == "bootstrap" or (stage is None and not api_ready)
    play = "verify" if args.command == "verify" else ("bootstrap" if bootstrap else "deploy")
    playbook = ROOT / "playbooks" / (play + ".yml")
    if not playbook.is_file():
        raise Checkpoint("Required playbook is not available yet: playbooks/%s.yml. No fallback to full site.yml; no host contacted." % play)
    command = ["ansible-playbook", "--inventory", str(args.inventory), str(playbook), "--limit", "localhost," + name]
    if not (os.environ.get("ANSIBLE_VAULT_PASSWORD_FILE") or os.environ.get("ANSIBLE_VAULT_IDENTITY_LIST")):
        command.append("--ask-vault-pass")
    if not args.no_become_prompt:
        if sys.stdin.isatty():
            command.append("--ask-become-pass")
        else:
            print("No terminal: become uses configured protected Ansible credentials or passwordless sudo. No password will be read from stdin.", flush=True)
    print("Running %s for infra only; rCTF is excluded." % playbook.name, flush=True)
    result = subprocess.run(command, cwd=ROOT)
    if result.returncode:
        return result.returncode
    if args.command == "verify":
        print("Verification playbook completed. Acceptance is limited to checks actually executed; missing external probes remain pending.")
    elif bootstrap:
        print("Bootstrap checkpoint reached. Installation/acceptance is incomplete. Obtain the loopback Technitium API token and single-use enrollment token using the CA helper; store them with ansible-vault edit, remove microlab_step_ca_initial_deploy if you set it for this first CA deployment, then run ./microlab deploy --stage services. First enrollment needs a fresh token; later convergence uses the existing renewable certificate.")
    else:
        print("Deployment playbook completed. Run ./microlab verify for acceptance; remote denial probes require real vantages.")
    return 0


def status(args):
    print("Local controller prerequisites:")
    for name in ("ansible-playbook", "ansible-inventory", "ansible-vault"):
        print("  %s: %s" % (name, "available" if shutil.which(name) else "missing (python3 -m pip install ansible-core PyYAML)"))
    print("  inventory: " + ("present" if args.inventory.is_file() else "missing; run ./microlab setup"))
    try:
        encrypted = []
        _, values = inspection(args, skipped=encrypted)
        missing = readiness(values)
        # Unopened Vault files may hold the non-file CA values; never call those missing.
        hidden = [key for key in missing if key in CA_VALUES] if encrypted else []
        missing = [key for key in missing if key not in hidden]
        print("  offline CA local inputs: " + ("pending: " + ", ".join(missing) if missing else "present; cryptographic validation still required" if not hidden else "file inputs present"))
        if hidden:
            print("  offline CA protected values: not visible without Vault (encrypted or still missing; deploy checks them): " + ", ".join(hidden))
        if encrypted:
            print("  encrypted vars files: %d present, not opened by status" % len(encrypted))
        print("  artifact declarations: " + ("present; integrity not checked by status" if values.get("micolab_staged_artifacts") else "missing; run ./microlab artifacts"))
    except Checkpoint as error:
        print("  configuration: " + str(error))
    print("Remote installation: UNVERIFIED. Acceptance: UNVERIFIED. No hosts contacted. Use ./microlab verify explicitly.")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="./microlab", description="MicroLab two-host controller. setup/artifacts/status are local; deploy/verify explicitly contact infra.")
    parser.add_argument("--inventory", type=Path, default=ROOT / "inventories/site/hosts.yml", help="reuse your existing YAML inventory")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("setup", help="create or conservatively complete local site inventory and Vault")
    for name in ("infra-ip", "ssh-user", "ssh-key", "arch", "rctf-ip"):
        create.add_argument("--" + name)
    create.add_argument("--admin-cidr", action="append", help="specific admin workstation /32 or protected VPN; repeatable")
    create.add_argument("--client-cidr", action="append", help="player network; repeatable (may contain admin /32)")
    artifacts = sub.add_parser("artifacts", help="stage pinned controller artifacts with the artifact module")
    artifacts.add_argument("--offline", action="store_true", help="use existing staged files only; no downloads")
    artifacts.add_argument("--check", action="store_true", help="inspect existing staged files without downloads or metadata writes")
    for name in ("deploy", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--no-become-prompt", action="store_true", help="use existing passwordless sudo or protected Ansible become credentials")
        if name == "deploy":
            command.add_argument("--stage", choices=("bootstrap", "services"), help="bootstrap: DNS/CA/Caddy credential checkpoint; services: continue or reconverge services (first enrollment needs a fresh token)")
    sub.add_parser("status", help="local prerequisites only; never contacts hosts or claims installation")
    # Accept --inventory on either side of the verb, keeping one stable contract.
    for command in sub.choices.values():
        command.add_argument("--inventory", type=Path, default=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    args.inventory = args.inventory.expanduser().resolve()
    try:
        if yaml is None:
            raise Checkpoint("Install controller dependencies: python3 -m pip install ansible-core PyYAML")
        if args.command == "setup":
            setup(args)
        elif args.command == "status":
            status(args)
        elif args.command == "artifacts":
            module = ROOT / "scripts/microlab_artifacts.py"
            if not module.is_file():
                raise Checkpoint("Artifact module is not available yet: scripts/microlab_artifacts.py")
            command = [sys.executable, str(module), "--inventory", str(args.inventory), "--directory", str(ROOT / "artifacts")]
            if args.offline:
                command.append("--offline")
            if args.check:
                command.append("--check")
            return subprocess.run(command, cwd=ROOT).returncode
        else:
            return execute_playbook(args)
        return 0
    except (Checkpoint, FileExistsError) as error:
        print("Checkpoint: " + (str(error) if isinstance(error, Checkpoint) else "A destination already exists; no existing file was replaced. Rerun setup to inspect it."), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, AttributeError, KeyError, yaml.YAMLError):
        print("Checkpoint: Cannot safely process local configuration. Review file shapes, permissions and inputs privately; no external tool output or secret values were logged.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
