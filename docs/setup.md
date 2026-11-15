# Advanced configuration and legacy site deployment

For the separate workload machine's OS installation, use
[Install Debian on the rCTF host](rctf-debian-install.md). The target preparation
in this advanced reference describes the infra host, not the microVM host.

Start with [fresh-clone onboarding](fresh-clone.md). This preserved reference
covers the older `playbooks/site.yml` workflow and detailed manual inputs.
Its expected assertion failures are **not** the staged CLI bootstrap contract.
Do not follow its numbered sections as prerequisites for `./microlab setup`.
External probe environments are for later acceptance; they do not require
additional physical installation hosts. Reuse existing inventory without copying
example values over it. The topology is exactly two hosts: all four infra
services together, and rCTF plus microVMs on the separate workload host.

---

# Fresh clone to first deployment

This is the operator runbook for the repository published at
[`7ad3463`](https://github.com/Caden64/microlab-ansible/commit/7ad346347dc0cb2a37d8afa37258d405eb40400f).
It describes the current role interfaces, including the two different variable
prefixes. Commands below are instructions for you to run; writing this guide
did not deploy anything.

**Status:** experimental. The recorded 258-test pass is local test evidence,
not a real-host deployment. There is a known acceptance compatibility question:
verify requires a loopback-only TCP 8053 listener, while Technitium has no
independent DoH bind-address setting. Firewall/proxy ACLs do not establish a
loopback bind. If the selected release listens on a wildcard address, stop at
that gate and resolve the implementation discrepancy; changing inventory alone
is not a verified fix. See [validation](validation.md).

## 1. Create your private inventory from the supplied example

**`inventories/site/` does not exist in a fresh clone. You create it in this
step.** `site` is the local directory name used throughout this guide for your
deployment configuration; it is not another download or an Ansible-generated
directory. The repository supplies `inventories/example/` as the starting point.

The **controller** is the computer where you clone this repository and run
Ansible. The **target** is the Debian management host Ansible will configure.
Run this step on the controller, not the target. You need Git installed first.

If you have not cloned the repository yet:

```bash
git clone https://github.com/Caden64/microlab-ansible.git
cd microlab-ansible
```

If you already cloned it, open a terminal in that existing checkout instead.
For example, if you cloned to `/home/caden64/projects/microlab/ansible`, run
`cd /home/caden64/projects/microlab/ansible`. Do not clone a second copy inside it.
The repository root is the directory containing `ansible.cfg`, `README.md`,
`roles/`, and `inventories/`.

Before copying, the supplied inventory files are:

```text
inventories/
├── example/
│   ├── hosts.yml
│   └── group_vars/
│       └── microlab_management/
│           └── main.yml
└── vault.yml.example
```

From the repository root, run this once:

```bash
umask 077
if [ -e inventories/site ]; then
  echo 'inventories/site already exists; keep it and inspect its files.'
else
  cp -a inventories/example inventories/site
  chmod 700 inventories/site
fi
ls -l inventories/site/hosts.yml \
  inventories/site/group_vars/microlab_management/main.yml
git check-ignore inventories/site/hosts.yml
```

`cp -a` creates `site/` and copies the example's files and subdirectories into
it. The `ls` command must show both copied files. The last command must print
`inventories/site/hosts.yml`, confirming Git excludes your private configuration.
If `site/` already exists but either file is missing, inspect that directory
before proceeding; do not overwrite an existing deployment's inputs.

Your new directory now contains:

```text
inventories/site/
├── hosts.yml                         # copied; edit in section 4
└── group_vars/
    └── microlab_management/
        └── main.yml                  # copied; replace in section 5
```

**There is no `vault.yml` yet.** You will create it with `ansible-vault create`
in section 8. `inventories/vault.yml.example` is a reference file; copying the
`example/` directory does not copy that separate file or create encrypted secrets.

`inventories/site/` is intentionally ignored by Git because it will contain your
real configuration. It will not appear on GitHub or in another fresh clone.
Some editors also hide ignored files; use the terminal `ls` above to check it.
Keep a separate protected backup of this directory. Never force-add it.

### Files you will edit after the copy

Run subsequent controller commands from this repository root unless stated otherwise.
In this guide:

- A `bash` block contains terminal commands. A `yaml` block contains file
  contents to paste into the named file, **not** commands to run.
- `REPLACE_WITH_...`, `VERSION`, `ARCH`, `YOUR_USER`, and `/path/to/...` are
  placeholders, not directories or values supplied by the repository. Replace
  them before running a command or saving a usable configuration. The example
  `10.77.*` addresses also need to become your real addresses.
- An absolute path starts with `/`; a relative path such as `inventories/site`
  starts from your current directory. In YAML, use the full controller path,
  such as `/home/alex/.local/share/microlab-artifacts`; do not assume `$HOME`
  expands inside a YAML string.
- Commands marked **TARGET**, **PROBE HOST**, or **OFFLINE MACHINE** run in a
  terminal on that machine. Other commands run on the controller. `sudo` applies
  to the machine where the command runs; it does not connect to another host.
- Read each block before executing it. A later instruction to **append** adds
  new keys to the same file; it does not replace earlier sections. Define each
  YAML key only once. Keep indentation as shown and use spaces, not tabs.

Keep the service names `ns1`, `ca`, `dns`, and `git` under `microlab.hnh`, with
the authoritative zone `hnh`. Renaming the domain is outside this runbook:
several CA constraints explicitly require these names.

| File or location | Your change |
| --- | --- |
| `inventories/site/hosts.yml` | Management IP, SSH account/key, external probe hosts. |
| `inventories/site/group_vars/microlab_management/main.yml` | Network policy, architecture, artifact pins/paths, CA public inputs, acceptance inputs. |
| `inventories/site/group_vars/microlab_management/vault.yml` | Encrypted passwords, application secrets, JWK inputs, API/enrollment/Git tokens. |
| Controller directory outside the checkout | Reviewed binaries/archives and protected intermediate CA source files. |
| Target `/srv/microlab/artifacts` | The two step-ca/step archives, staged before deployment. |
| Target `/root/microlab-acceptance` | Dedicated Git acceptance SSH key and pinned `known_hosts`, created after Forgejo starts. |
| Probe hosts | Tooling, actual source addresses/routing, readable public CA certificate. |

Do not edit role defaults/templates or the shared `group_vars/all.yml` to set
your site. Inventory group variables override shared `all` defaults. The
`playbooks/group_vars` symlink loads those shared defaults for site/backup/restore.
Use **`micolab_`** for shared/DNS/Caddy/Forgejo/verify variables and
**`microlab_`** for canonical CA/TLS variables exactly as shown.

## 2. Prepare the controller tools

```bash
git rev-parse HEAD
```

Record this commit as the version you deploy and preserve a copy of the
bootstrap repo outside Forgejo. The private inventory was created in section 1;
all later `inventories/site/...` paths refer to that copy.

On a Debian-family **controller**, install Git, OpenSSH client, OpenSSL,
Python 3 and venv support. Install a reviewed Ansible Core **2.16 or newer** in
a venv, for example:

```bash
sudo apt-get update
sudo apt-get install git openssh-client openssl python3 python3-venv ripgrep nano
python3 -m venv .venv
. .venv/bin/activate
# Replace with the exact reviewed version compatible with your Python.
python -m pip install 'ansible-core==REPLACE_WITH_CONTROLLER_ANSIBLE_VERSION'
ansible-playbook --version
```

The venv is the local `.venv/` directory created by `python3 -m venv`; it does
not exist in the clone. In every new controller terminal, return to the repo
and run `. .venv/bin/activate` before Ansible commands. The leading `.` is the
shell's activation command, not a typo. `which ansible-playbook` should point
inside this checkout's `.venv/bin/`. Do not run Ansible itself with `sudo` on
the controller; Ansible uses sudo on the target where required.

Use `nano inventories/site/hosts.yml` to open the copied host file, and
`nano inventories/site/group_vars/microlab_management/main.yml` for site settings.
In nano, paste/edit the named block, press **Ctrl+O**, **Enter** to save, then
**Ctrl+X** to exit. You can use a different local editor if you prefer. For
encrypted secrets use `ansible-vault edit`, never edit the ciphertext with nano.

Before an air gap, retain the exact Python package wheels and transitive
dependencies; install them with `--no-index --find-links=/path/to/wheels`.
There are no Galaxy collections/roles to install from `requirements.yml`.
The optional development test dependencies are listed in [validation](validation.md).

Use a protected editor for inventory. Ansible Vault editors can create temporary
plaintext files; disable swap/backup files and use an encrypted controller disk.

## 3. Prepare the target before Ansible

Use a dedicated **Debian 12 or 13**, systemd, 64-bit `arm64` or `amd64` machine.
Use an SSD-backed root filesystem for this first layout. That puts the default
state directories on SSD without changing multiple role and backup interfaces:

| Target path | Persistent state |
| --- | --- |
| `/etc/dns` | Technitium settings/zones and native DNS certificate material. |
| `/etc/step-ca` | Intermediate material, CA configuration and database. |
| `/var/lib/caddy` | Caddy certificate/account state. |
| `/var/lib/forgejo` | SQLite, repositories, LFS, attachments and application data. |
| `/etc/forgejo/app.ini` | Forgejo configuration and durable secrets. |
| `/etc/technitium-tls` | Renewal environment/credentials. |
| `/var/lib/technitium-tls` | Durable renewal lock and status. |

If your OS boots from SD, arrange persistent mounts at the required paths
before deploying. Merely mounting an SSD at `/mnt/ssd` does not move any of
these directories. `micolab_required_storage_path` is a validation path, not a
data relocation switch. Custom paths require coordinated role and backup inputs;
see [backup/restore](backup-restore.md).

On the **target**, with its initial resolver and package mirror still working:

Use the machine's console or an already working administrative session for this
OS preparation. On minimal Debian without `sudo`, log in as root and omit
`sudo` from the package commands until it is installed. The repository does
not install Debian, mount an SSD, or create your operator SSH account.

```bash
sudo apt-get update
sudo apt-get install python3 sudo openssh-server ca-certificates curl \
  bind9-dnsutils knot-dnsutils git git-lfs gzip iproute2 logrotate nftables \
  openssl tar util-linux libicu-dev nano
timedatectl show -p NTPSynchronized --value
sudo sshd -T | grep '^port '
findmnt -T /var/lib
sudo ss -lntup
ls -l /etc/resolv.conf
```

### Establish your management SSH account

If you already have an SSH account with working sudo, keep it and use that name
in inventory. Otherwise, from the **target console** after installing sudo,
create one (the example name is `microlab-ansible`):

```bash
# TARGET CONSOLE: run as root, or prefix with sudo from an existing admin.
adduser microlab-ansible
usermod -aG sudo microlab-ansible
systemctl enable --now ssh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Choose a strong account password when `adduser` prompts. Record the printed
**host-key fingerprint** for authenticating the target. This is separate from
your login key and from the private CA fingerprint created later.

On the **controller**, create a dedicated login key if you do not already have
one. Do not overwrite an existing key when prompted:

```bash
install -d -m 0700 "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/microlab_ansible" -C microlab-controller
```

Use a passphrase for this operator key. Load it in your existing SSH agent with
`ssh-add "$HOME/.ssh/microlab_ansible"`. If `ssh-add` says no agent is available,
start one in that terminal with `eval "$(ssh-agent -s)"`, then run `ssh-add` again.
The `.pub` file is public; the file without `.pub` is private and stays on the
controller. Ansible needs the private key's absolute path.

If password SSH login is permitted for the new account, authorize the public
key from the controller:

```bash
ssh-copy-id -i "$HOME/.ssh/microlab_ansible.pub" \
  microlab-ansible@REPLACE_WITH_MANAGEMENT_IP
ssh -i "$HOME/.ssh/microlab_ansible" \
  microlab-ansible@REPLACE_WITH_MANAGEMENT_IP
```

Compare the SSH fingerprint prompt with the fingerprint from the target console
before accepting it. If password SSH is disabled, use the **target console**
instead: create `/home/microlab-ansible/.ssh` owned by `microlab-ansible` with mode
0700, paste the controller's entire `.pub` line into `authorized_keys`, and set
that file to the same owner with mode 0600. For example:

```bash
# TARGET CONSOLE as root; paste only the PUBLIC key in the editor.
install -d -m 0700 -o microlab-ansible -g microlab-ansible \
  /home/microlab-ansible/.ssh
nano /home/microlab-ansible/.ssh/authorized_keys
chown microlab-ansible:microlab-ansible /home/microlab-ansible/.ssh/authorized_keys
chmod 0600 /home/microlab-ansible/.ssh/authorized_keys
```

After SSH login, run `sudo -v` on the target; it should accept this account's
password. Keep the console available until both SSH and sudo work. Prepare
probe login accounts/public keys the same way, but the delegated probes do not
need sudo privileges. Their initial package installation still needs an admin.

### Complete the time, resolver and network prerequisites

`libicu-dev` pulls in Debian's matching libicu runtime. Also stage the native
dependencies required by your selected .NET release for this OS. In an air gap,
provide all `.deb` dependencies or an offline apt source; the roles do not solve
package availability. The CA role runs apt without refreshing package indexes.

Configure your chosen time daemon to use a reachable internal time source;
the `timedatectl` check must return **`yes`**, including during WAN outages.
OpenSSH must listen on **22**. Resolve existing users of ports 53, 80, 443,
853, 3000, 4443, 5380, 8053 and 2019 before deployment. Also reserve UDP
`127.0.0.1:5353` for the managed DNS fixture. Do not blindly stop the
current resolver: preserve a working bootstrap DNS path until the DNS gates pass.

By default Ansible replaces `/etc/resolv.conf` after DNS acceptance and requires
it to be a regular file. A systemd-resolved/NetworkManager-managed symlink fails
closed. Either arrange a regular, intentionally unmanaged resolver file or set
`micolab_dns_manage_resolv_conf: false` and configure your existing resolver
manager to use Technitium once it is healthy. In the latter case, ensure the
target itself resolves `*.microlab.hnh` before step-ca/Caddy issuance.

The package commands do **not** configure your time daemon, stable IP or resolver
manager. Configure these through the OS/network tools used by your installation
before continuing. There is no universal safe command for replacing an unknown
NetworkManager/systemd-resolved setup. Setting `micolab_dns_manage_resolv_conf:
false` alone does not free port 53 or configure local name resolution. If port
53 is occupied or `NTPSynchronized` is not `yes`, stop here and finish that OS
preparation; do not proceed expecting a later role to fix it.

Collect your real network values before filling in the examples. On the target
and each probe, `ip -4 address` shows assigned addresses. On each probe run
`ip -4 route get REPLACE_WITH_MANAGEMENT_IP` and record its `src` address. On an
existing SSH session to the target, `printf '%s\n' "$SSH_CONNECTION"` shows the
controller's source address as the first field. Account for NAT/VPN routing:
the target's firewall sees the post-routing source, and different acceptance
classes must remain distinguishable. A declared DNS/DoT source must actually
be configured on that probe. Inventory does not create VLANs, routes, VPNs or
probe machines. Five aliases for one ordinary network connection do not create
five independent vantage points.

Verify the management SSH host-key fingerprint against its console or another
trusted channel. Connect once and accept only that verified key. Do the same for
every probe host. Host-key checking stays enabled. Your SSH account needs sudo;
the commands below use `--ask-become-pass` where needed. The playbook installs an
nftables input policy **and a forward-chain drop policy**: this host should not
also be an unreviewed router/container networking gateway.

## 4. Set `inventories/site/hosts.yml`

Replace the copied file with this structure, substituting real addresses and
accounts. The IPs below describe an **illustrative routed lab**, not values to
apply unchanged. Probes must exist; adding inventory entries does not create
interfaces or routes. HTTP probes use the host's actual route-selected source;
DNS and DoT probes bind the explicitly supplied source address.

```yaml
all:
  children:
    microlab_management:
      hosts:
        microlab-mgmt:
          ansible_host: 10.77.10.10
          ansible_user: REPLACE_WITH_MANAGEMENT_SSH_USER
          ansible_ssh_private_key_file: /REPLACE_WITH_CONTROLLER_SSH_KEY
          ansible_python_interpreter: /usr/bin/python3
    microlab_challenge:
      hosts: {}
    microlab_probes:
      vars:
        ansible_user: REPLACE_WITH_PROBE_SSH_USER
        ansible_ssh_private_key_file: /REPLACE_WITH_CONTROLLER_PROBE_KEY
        ansible_python_interpreter: /usr/bin/python3
      hosts:
        probe-admin:
          ansible_host: 10.77.10.20
        probe-client:
          ansible_host: 10.77.20.20
        probe-authoritative:
          ansible_host: 10.77.30.20
        probe-no-doh:
          ansible_host: 10.77.40.20
        probe-outside:
          ansible_host: 10.77.50.20
```

Keep the management host out of the challenge group. Probe hosts need SSH
access from the controller, Bash, `dig`, `curl`, Python 3 and writable `/tmp`.
Both DNS remote probes and verify's HTTPS/DoT probes run without sudo. Package
and public-trust preparation needs administrative access on those hosts; the
probe SSH account itself does not need sudo for the delegated probes.

## 5. Replace the site `main.yml`: network and storage

Replace the contents of
`inventories/site/group_vars/microlab_management/main.yml` with this block.
Append the later non-secret blocks to this **same file**, with each key defined
only once. Replace the sample addresses consistently in hosts, CIDRs, DNS
records and probe definitions.

```yaml
---
micolab_expected_os: Debian
micolab_expected_architecture: arm64  # amd64 for an x86-64 host
micolab_ssh_port: 22

micolab_admin_cidrs: [10.77.10.0/24]
micolab_client_cidrs: [10.77.20.0/24, 10.77.40.0/24]
micolab_dns_authoritative_only_cidrs: [10.77.30.0/24]
micolab_dns_recursion_allow_cidrs: []
micolab_admin_cidrs_v6: []
micolab_client_cidrs_v6: []
micolab_dns_authoritative_only_cidrs_v6: []

micolab_dns_addresses:
  ns1: 10.77.10.10
  ca: 10.77.10.10
  dns: 10.77.10.10
  git: 10.77.10.10
micolab_dns_ipv6_enabled: false
micolab_dns_ipv6_addresses: {}
micolab_dns_forwarders: []
micolab_dns_allow_online_forwarders: false
micolab_dns_manage_resolv_conf: true

# The fixture returns a known answer; no machine has to own the answer IP.
micolab_dns_fixture_upstream: "127.0.0.1:5353"
micolab_dns_fixture_zone: fixture.test
micolab_dns_fixture_name: probe.fixture.test
micolab_dns_fixture_expected_ip: 10.77.254.1
micolab_dns_fixture_manage_service: true
micolab_dns_fixture_listen_address: "127.0.0.1"
micolab_dns_fixture_port: 5353

# Deliberately narrower than the firewall's web-client list. The .40 network
# can reach HTTPS but receives HTTP 403 for DoH, providing a real denial test.
micolab_caddy_dns_client_cidrs: [10.77.10.0/24, 10.77.20.0/24]

micolab_required_storage_path: /etc/dns
micolab_min_free_bytes: 2147483648
micolab_max_powered_off_interval_seconds: 86400
micolab_trust_targets:
  - {name: ca.microlab.hnh, role: step_ca}
  - {name: git.microlab.hnh, role: forgejo}

# Chosen now; created manually after Forgejo first starts.
micolab_verify_git_repo: microlab-admin/deployment-check
micolab_verify_git_visibility: private
micolab_verify_ssh_private_key: /root/microlab-acceptance/id_ed25519
micolab_verify_known_hosts: /root/microlab-acceptance/known_hosts

# Target-local, outside backed-up trees; create before backup in section 15.
micolab_backup_destination: /srv/microlab-backups
```

Include the controller's **actual source address as seen by the target** in
admin CIDRs. Include the management host's own routed source address too:
step-ca calls Caddy over port 80, and local Git acceptance connects to the
public Git name on port 22. The example management subnet covers both.
Do not put authoritative-only clients inside admin/client networks. SSH,
including normal Git-over-SSH, is limited to admin networks in this implementation.

The `.40` network is deliberately a DNS-recursion/web client but not a DoH
client; it is not an authoritative-only network. This separation is necessary
for the current HTTP-403 acceptance contract. Choose the equivalent real
policy for your lab. An outside-firewall host cannot substitute for this probe.

The powered-off interval is a declared requirement, not a timer that extends
certificates. Choose your actual interval. Seven-day leaves renew early, but
remaining validity at shutdown varies; an expired certificate needs protected
re-enrollment. Two GiB is only a minimum gate, not a capacity recommendation.

## 6. Pin and stage artifacts

Select releases compatible with the code and your OS; this guide does not
choose current versions or invent checksums. Verify publisher signatures or
authenticated checksum manifests, then hash the exact files you stage:

The repository includes **no release binaries**. First create a controller
artifact directory outside the checkout:

```bash
# CONTROLLER
install -d -m 0700 "$HOME/.local/share/microlab-artifacts"
realpath "$HOME/.local/share/microlab-artifacts"
```

Use the printed absolute path in place of `/absolute/controller/artifacts` and
`/REPLACE_WITH_CONTROLLER_ARTIFACT_DIR` below. Download or transfer each selected
release into that directory before running `sha256sum`. The hash command does
not download anything. This repo has no reviewed release compatibility matrix
or manifest bundle; selecting and authenticating those exact releases is a
required preparation input, not something an omitted command already did.

```bash
sha256sum /absolute/controller/artifacts/*
tar -tzf /absolute/controller/artifacts/REPLACE_WITH_ARCHIVE.tar.gz
```

Local hashes detect transfer changes; they do not authenticate an untrusted
download. Preserve the verified manifests and artifacts outside Forgejo.

| Artifact | Required layout and location |
| --- | --- |
| Technitium portable tar.gz | Controller; `DnsServerApp.dll`/`DnsServerCore.dll` extract directly into install directory. |
| ASP.NET Core runtime tar.gz | Controller; `dotnet` extracts at archive root; select the target architecture. |
| Stock Caddy tar.gz | Controller; contains `caddy` at root. |
| Official Forgejo binary | Controller; executable for target architecture, **not** a tarball. |
| `step-ca_linux_VERSION_ARCH.tar.gz` | Target `/srv/microlab/artifacts`; contains `step-ca` at root. |
| `step_linux_VERSION_ARCH.tar.gz` | Target same directory; contains `step_VERSION/bin/step`. |

Use `arm64` or `amd64` for this role's artifact architecture. The .NET download
may call amd64 `x64`; choose correct bytes even when a publisher uses a different
filename. The checked-in runtime-major default is `10` for Technitium 15.x.
Confirm the chosen release's runtime requirement and set the major explicitly.

Append to site `main.yml` (replace every `REPLACE_`):

```yaml
micolab_technitium_version: "REPLACE_WITH_TECHNITIUM_VERSION"
micolab_technitium_runtime_major: "10"
micolab_staged_artifacts:
  - name: technitium
    version: "REPLACE_WITH_TECHNITIUM_VERSION"
    path: /REPLACE_WITH_CONTROLLER_ARTIFACT_DIR/DnsServerPortable.tar.gz
    sha256: "REPLACE_WITH_TECHNITIUM_SHA256"
  - name: dotnet-aspnetcore-runtime
    version: "REPLACE_WITH_ASPNETCORE_VERSION"
    path: /REPLACE_WITH_CONTROLLER_ARTIFACT_DIR/aspnetcore-runtime.tar.gz
    sha256: "REPLACE_WITH_ASPNETCORE_SHA256"
  - name: caddy
    version: "REPLACE_WITH_CADDY_VERSION"
    path: /REPLACE_WITH_CONTROLLER_ARTIFACT_DIR/caddy.tar.gz
    sha256: "REPLACE_WITH_CADDY_SHA256"
  - name: forgejo
    version: "REPLACE_WITH_FORGEJO_VERSION"
    path: /REPLACE_WITH_CONTROLLER_ARTIFACT_DIR/forgejo
    sha256: "REPLACE_WITH_FORGEJO_SHA256"

microlab_step_ca_artifact_base_url: file:///srv/microlab/artifacts
microlab_step_ca_version: "REPLACE_WITH_STEP_CA_VERSION"
microlab_step_ca_checksums:
  arm64: "REPLACE_WITH_STEP_CA_ARM64_SHA256"
microlab_step_cli_version: "REPLACE_WITH_STEP_CLI_VERSION"
microlab_step_cli_checksums:
  arm64: "REPLACE_WITH_STEP_CLI_ARM64_SHA256"
```

For amd64, change both checksum-map keys to `amd64` and stage those artifacts.
All checksums are 64 hex characters. Caddy/Forgejo versions must be `X.Y.Z`
without `v`. Leave their separate `micolab_caddy_version` and
`micolab_forgejo_version` variables unset: the roles adopt version, path and hash
from these staged entries **only when their explicit version is empty**.

The four `micolab_staged_artifacts` entries are copied by their roles. The two
CA archives need a separate transfer. Create the SSH user's upload directory
and copy those archives from the **controller**; replace the key/account/IP and
filenames first:

```bash
ssh -i /REPLACE_WITH_CONTROLLER_SSH_KEY \
  REPLACE_WITH_MANAGEMENT_SSH_USER@REPLACE_WITH_MANAGEMENT_IP \
  'install -d -m 0700 "$HOME/microlab-upload"'
scp -i /REPLACE_WITH_CONTROLLER_SSH_KEY \
  /REPLACE_WITH_CONTROLLER_ARTIFACT_DIR/step-ca_linux_VERSION_ARCH.tar.gz \
  /REPLACE_WITH_CONTROLLER_ARTIFACT_DIR/step_linux_VERSION_ARCH.tar.gz \
  REPLACE_WITH_MANAGEMENT_SSH_USER@REPLACE_WITH_MANAGEMENT_IP:microlab-upload/
```

Then log in to the **target as that same SSH user** and install them using sudo:

```bash
# TARGET: replace names with exact pinned version and architecture.
sudo install -d -m 0755 /srv/microlab/artifacts
sudo install -m 0644 "$HOME/microlab-upload/step-ca_linux_VERSION_ARCH.tar.gz" \
  /srv/microlab/artifacts/step-ca_linux_VERSION_ARCH.tar.gz
sudo install -m 0644 "$HOME/microlab-upload/step_linux_VERSION_ARCH.tar.gz" \
  /srv/microlab/artifacts/step_linux_VERSION_ARCH.tar.gz
sha256sum /srv/microlab/artifacts/*.tar.gz
```

Compare target hashes with the authenticated controller hashes. `VERSION` in
each filename is that component's own pin; step-ca and step CLI versions may
differ. Renaming an archive does not change its internal layout. `ARCH` is the
target's `arm64` or `amd64`, regardless of the controller's CPU.

Do not substitute controller paths into `file:///srv/...`: `get_url` opens those
files **on the target**. Conversely, all `micolab_staged_artifacts[].path` values
and the CA `*_src` values below are **absolute controller paths**.

## 7. Create the CA offline and export only deployment material

Use a separate trusted offline machine with a verified, pinned `step` CLI,
OpenSSL and Python 3. Never run this initialization on the Ansible controller or target.
If an existing CA is being recovered, use [CA recovery](ca-recovery.md) instead;
a fresh Git clone is not permission to generate a replacement trust root.

The following creates a new offline CA in a **new directory**, with separate
root and deployed intermediate passwords. Set `STEPPATH` to your real encrypted
offline location; the example directory must not already exist.
Mount and unlock your encrypted offline storage first; the command below creates
the `microlab-ca` child, not the parent volume or its encryption. Confirm `step
version` and `openssl version` work on that machine before starting.

```bash
# OFFLINE MACHINE ONLY
umask 077
export STEPPATH=/REPLACE_WITH_ENCRYPTED_OFFLINE_VOLUME/microlab-ca
(
set -eu
mkdir -m 0700 "$STEPPATH"
openssl rand -base64 48 > "$STEPPATH/root-password.txt"
openssl rand -base64 48 > "$STEPPATH/intermediate-password.txt"
openssl rand -base64 48 > "$STEPPATH/admin-provisioner-password.txt"
openssl rand -base64 48 > "$STEPPATH/technitium-provisioner-password.txt"
step ca init --deployment-type standalone --name 'MicroLab Intermediate CA' \
  --dns ca.microlab.hnh --dns 127.0.0.1 --address 127.0.0.1:4443 \
  --password-file "$STEPPATH/root-password.txt" --provisioner admin \
  --provisioner-password-file "$STEPPATH/admin-provisioner-password.txt"
step ca provisioner add acme --type ACME \
  --ca-config "$STEPPATH/config/ca.json" \
  --x509-min-dur 5m --x509-max-dur 168h --x509-default-dur 168h
step ca provisioner add microlab-technitium --type JWK --create \
  --ca-config "$STEPPATH/config/ca.json" \
  --password-file "$STEPPATH/technitium-provisioner-password.txt" \
  --x509-min-dur 5m --x509-max-dur 168h --x509-default-dur 168h
mkdir -m 0700 "$STEPPATH/deployment-export"
cp "$STEPPATH/certs/root_ca.crt" "$STEPPATH/deployment-export/"
cp "$STEPPATH/certs/intermediate_ca.crt" "$STEPPATH/deployment-export/"
# Re-encrypt only the exported intermediate; never export root-key material.
openssl pkcs8 -topk8 -v2 aes-256-cbc \
  -in "$STEPPATH/secrets/intermediate_ca_key" \
  -passin "file:$STEPPATH/root-password.txt" \
  -passout "file:$STEPPATH/intermediate-password.txt" \
  -out "$STEPPATH/deployment-export/intermediate_ca_key"
step certificate fingerprint "$STEPPATH/certs/root_ca.crt"
)
```

The parentheses and `set -eu` make this block stop on an error, including an
already-existing CA directory. Do not bypass that guard or run the remaining
lines after a failure: existing escrow passwords must never be overwritten.
Investigate partial initialization using the offline recovery plan.

Retain the last fingerprint through an independently trusted channel. Extract
the `key` object and `encryptedKey` string from the `microlab-technitium`
provisioner in offline `config/ca.json`. `key` must be the public EC JWK with
`kty`, `kid`, `x`, `y` (normally `crv: P-256`) and **no** private `d` field.
Keep the Technitium JWK password in protected operator custody for later token
minting. The live role renders its own two-provisioner config and server-only
certificate template; do not copy the offline `ca.json` to the host.

To extract the two JWK values without copying the full CA config, run on the
**offline machine**, in the same shell where you set `STEPPATH`:

```bash
python3 - <<'PY'
import json, os
from pathlib import Path
base = Path(os.environ['STEPPATH'])
config = json.loads((base / 'config/ca.json').read_text())
matches = [p for p in config['authority']['provisioners']
           if p['name'] == 'microlab-technitium']
assert len(matches) == 1, 'Expected one Technitium provisioner'
p = matches[0]
assert p['type'] == 'JWK'
assert all(k in p['key'] for k in ('kty', 'kid', 'x', 'y'))
assert 'd' not in p['key'], 'Do not export a decrypted private JWK'
fields = {'microlab_step_ca_technitium_jwk_key': p['key'],
          'microlab_step_ca_technitium_jwk_encrypted_key': p['encryptedKey']}
out = base / 'technitium-vault-fields.json'
with out.open('x') as f:
    json.dump(fields, f, indent=2)
    f.write('\n')
out.chmod(0o600)
PY
```

That file contains the named values to enter in Vault in section 8. It is not
a complete Vault file. Keep it protected along with the intermediate password
during transfer. The script refuses to overwrite an existing export.

These offline provisioner operations use explicit `--ca-config`, rather than
requiring a running CA. See [Smallstep's CLI reference](https://smallstep.com/docs/step-cli/reference/ca/provisioner/add/).

Use protected removable media to transfer the three `deployment-export` files;
do not network the offline machine merely to run SCP. Mount/unlock the transfer
media on the offline machine first. Replace `/TRANSFER` with its actual mounted
encrypted volume path; do not create an ordinary directory and assume it is
encrypted media. After verifying the mount, copy only the listed inputs:

```bash
# OFFLINE MACHINE, in the shell with STEPPATH set; /TRANSFER is a mountpoint.
(
set -eu
mountpoint -q /TRANSFER
install -d -m 0700 /TRANSFER/deployment-export
install -m 0644 "$STEPPATH/deployment-export/root_ca.crt" /TRANSFER/deployment-export/
install -m 0644 "$STEPPATH/deployment-export/intermediate_ca.crt" /TRANSFER/deployment-export/
install -m 0600 "$STEPPATH/deployment-export/intermediate_ca_key" /TRANSFER/deployment-export/
install -m 0600 "$STEPPATH/intermediate-password.txt" /TRANSFER/
install -m 0600 "$STEPPATH/technitium-vault-fields.json" /TRANSFER/
sync
)
```

Unmount/lock the media safely before moving it. Mount/unlock it on the controller;
its mount path can differ there. The media now carries sensitive intermediate
inputs, not root escrow. Keep it protected. With `/TRANSFER` replaced by the
controller's actual mount path, create the input directory and copy the files:

```bash
# CONTROLLER: /TRANSFER/deployment-export must exist on the mounted media.
install -d -m 0700 "$HOME/.local/share/microlab-ca-inputs"
install -m 0644 /TRANSFER/deployment-export/root_ca.crt \
  "$HOME/.local/share/microlab-ca-inputs/root_ca.crt"
install -m 0644 /TRANSFER/deployment-export/intermediate_ca.crt \
  "$HOME/.local/share/microlab-ca-inputs/intermediate_ca.crt"
install -m 0600 /TRANSFER/deployment-export/intermediate_ca_key \
  "$HOME/.local/share/microlab-ca-inputs/intermediate_ca_key"
realpath "$HOME/.local/share/microlab-ca-inputs"
```

Use the printed path for `/REPLACE_WITH_CONTROLLER_CA_DIR` below. Transfer the
intermediate password/JWK fields into Vault using a protected channel. Keep
the root key, root password and full offline state
in separately recoverable offline escrow. Never copy the whole `STEPPATH` tree.

Append to site `main.yml`:

```yaml
microlab_step_ca_root_cert_src: /REPLACE_WITH_CONTROLLER_CA_DIR/root_ca.crt
microlab_step_ca_intermediate_cert_src: /REPLACE_WITH_CONTROLLER_CA_DIR/intermediate_ca.crt
microlab_step_ca_intermediate_key_src: /REPLACE_WITH_CONTROLLER_CA_DIR/intermediate_ca_key
microlab_step_ca_root_fingerprint_sha256: "REPLACE_WITH_ROOT_CERT_SHA256_FINGERPRINT"
microlab_step_ca_initial_deploy: true
```

The fingerprint is the certificate DER SHA-256 from `step certificate fingerprint`,
not `sha256sum root_ca.crt` (which hashes the PEM file). Remove the initial-deploy
flag after the CA has successfully started and created its database, even if a
later phase fails. Never set recovery flags just to get past an error.

## 8. Create the encrypted `vault.yml`

```bash
EDITOR=nano ansible-vault create inventories/site/group_vars/microlab_management/vault.yml
```

This creates a new encrypted file; it is not copied from Git. Choose a new
**Vault unlock password** at the prompt and retain it in your password manager.
It is distinct from the SSH/sudo account password, CA intermediate password,
JWK provisioner password and application passwords. Saving/exiting the editor
encrypts the file. Later `--ask-vault-pass` asks for this Vault password;
`--ask-become-pass` asks for the target SSH account's sudo password.

Inside that editor, enter the following keys with your actual values. These are
direct role variable names; no `vault_...` indirection is needed. The encrypted
file is loaded automatically because it is inside the management group directory.
Keep passwords in this file, not in `main.yml` or shell `-e` arguments.
The files load alphabetically as group variables; encryption does not give a
variable special precedence. Define each setting once across `main.yml` and
`vault.yml`, and do not additionally define canonical TLS secret aliases that
would override the `micolab_...` keys shown here.

```yaml
---
micolab_technitium_admin_password: "REPLACE_WITH_RANDOM_PASSWORD_AT_LEAST_12_CHARACTERS"
micolab_technitium_tls_cert_password: "REPLACE_WITH_DURABLE_RANDOM_PFX_PASSWORD"
microlab_step_ca_intermediate_key_password: "REPLACE_WITH_EXPORTED_INTERMEDIATE_PASSWORD"
microlab_step_ca_technitium_jwk_key:
  kty: EC
  crv: P-256
  kid: "REPLACE_WITH_PUBLIC_JWK_KID"
  x: "REPLACE_WITH_PUBLIC_JWK_X"
  y: "REPLACE_WITH_PUBLIC_JWK_Y"
microlab_step_ca_technitium_jwk_encrypted_key: "REPLACE_WITH_ENCRYPTED_JWK_STRING"

micolab_forgejo_secret_key: "REPLACE_WITH_DURABLE_SECRET_KEY"
micolab_forgejo_internal_token: "REPLACE_WITH_DURABLE_INTERNAL_TOKEN"
micolab_forgejo_jwt_secret: "REPLACE_WITH_DURABLE_JWT_SECRET"
micolab_forgejo_lfs_jwt_secret: "REPLACE_WITH_DURABLE_LFS_JWT_SECRET"
micolab_forgejo_admin_username: microlab-admin
micolab_forgejo_admin_email: "REPLACE_WITH_REAL_ADMIN_EMAIL"
micolab_forgejo_admin_password: "REPLACE_WITH_RANDOM_PASSWORD_AT_LEAST_16_CHARACTERS"

# Intentionally empty for the first run; fill at the bootstrap checkpoints.
micolab_technitium_api_token: ""
micolab_technitium_enrollment_token: ""
micolab_verify_git_https_username: ""
micolab_verify_git_https_token: ""
```

Generate the four Forgejo secrets independently **once**, then retain them across
reruns and restores. With a verified Forgejo binary executable on your preparation
machine, its commands are `forgejo generate secret SECRET_KEY`, `INTERNAL_TOKEN`,
`JWT_SECRET` and `LFS_JWT_SECRET`. See the [Forgejo CLI reference](https://forgejo.org/docs/latest/admin/command-line/#generate-secret).
Do not try to execute an ARM binary on an amd64 controller.

Alternatively, use these independent generators on the controller. Each command
prints **one new value** to copy into the named Vault field; it does not edit
Vault automatically. Use a private terminal, not a recorded/shared session:

```bash
# micolab_forgejo_secret_key
openssl rand -hex 32
# micolab_forgejo_internal_token
openssl rand -hex 32
# micolab_forgejo_jwt_secret (32 bytes, unpadded base64url)
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'; printf '\n'
# micolab_forgejo_lfs_jwt_secret (generate a separate value)
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'; printf '\n'
# micolab_technitium_admin_password
openssl rand -hex 24
# micolab_technitium_tls_cert_password
openssl rand -hex 24
# micolab_forgejo_admin_password
openssl rand -hex 24
```

Copy each generated value into the matching encrypted field. Do not regenerate
them when repeating this runbook against an existing deployment. The Technitium
admin password must differ from `admin`. The Forgejo password must differ from
its username; use at least 16 characters. Safely quote YAML values containing
special characters. Leave only the four explicitly empty bootstrap fields empty.
The intermediate password and JWK fields already exist from section 7: copy
those exact values, do not generate replacements. To change Vault later:

```bash
EDITOR=nano ansible-vault edit inventories/site/group_vars/microlab_management/vault.yml
```

## 9. Define the acceptance probes before running

Append to site `main.yml`; replace sample addresses consistently:

```yaml
micolab_dns_remote_probes:
  - {host: probe-client, dns_server: 10.77.10.10, source_address: 10.77.20.20, access: recursion-allowed, fqdn: ca.microlab.hnh, expect_ip: 10.77.10.10}
  - {host: probe-authoritative, dns_server: 10.77.10.10, source_address: 10.77.30.20, access: recursion-denied, fqdn: ca.microlab.hnh, expect_ip: 10.77.10.10}
  - {host: probe-outside, dns_server: 10.77.10.10, source_address: 10.77.50.20, access: firewall-denied, fqdn: ca.microlab.hnh, expect_ip: 10.77.10.10}

micolab_verify_external_acl_probes:
  - {host: probe-admin, check: dns_admin, expect: allowed}
  - {host: probe-client, check: dns_admin, expect: denied}
  - {host: probe-admin, check: ca_management, expect: allowed}
  - {host: probe-client, check: ca_management, expect: denied}
  - {host: probe-client, check: doh, expect: allowed}
  - {host: probe-no-doh, check: doh, expect: denied}
  - {host: probe-client, check: dot, expect: allowed, source_address: 10.77.20.20, access: recursion-allowed}
  - {host: probe-authoritative, check: dot, expect: denied, source_address: 10.77.30.20, access: recursion-denied}
```

On **each probe host**, use an administrative session for package preparation:

```bash
# PROBE HOST (Debian-family example)
sudo apt-get update
sudo apt-get install bind9-dnsutils curl python3 bash ca-certificates openssl iproute2
```

Copy the verified **public root only** from the controller to each probe's SSH
account. Repeat this controller command for each probe IP/account/key from
`hosts.yml`; `microlab-root.crt` will be created in that probe user's home:

```bash
# CONTROLLER
scp -i /REPLACE_WITH_CONTROLLER_PROBE_KEY \
  "$HOME/.local/share/microlab-ca-inputs/root_ca.crt" \
  REPLACE_WITH_PROBE_SSH_USER@REPLACE_WITH_PROBE_IP:microlab-root.crt
```

Log in to each probe as that user, compare the fingerprint, then install trust:

```bash
# PROBE HOST: the file was just copied to this account's home directory.
openssl x509 -in "$HOME/microlab-root.crt" -noout -fingerprint -sha256
sudo install -m 0644 "$HOME/microlab-root.crt" \
  /usr/local/share/ca-certificates/microlab-root.crt
sudo update-ca-certificates
```

Compare the fingerprint with your recorded pin **before** the `install` command.
OpenSSL prints colon-separated bytes; ignoring colons and letter case, they must
equal the `step certificate fingerprint` value. The external
probes read that same certificate path by default; a per-probe `ca_file` changes
the read path if necessary. Install trust on actual browser/Git/DNS clients too;
some applications use a separate trust store. `micolab_trust_targets` is declared
intent, not remote trust-store automation.

As the unprivileged probe account, verify its source and readable CA path:

```bash
# PROBE HOST: replace with the real management IP and this probe's own IP.
ip -4 address show
ip -4 route get REPLACE_WITH_MANAGEMENT_IP
ip -4 route get REPLACE_WITH_MANAGEMENT_IP from REPLACE_WITH_THIS_PROBE_SOURCE_IP
test -r /usr/local/share/ca-certificates/microlab-root.crt
```

`test -r` prints nothing on success; `echo $?` immediately afterward should
print `0`. The source IP must appear in `ip address`, with working forward and
return routes. HTTP uses the route-selected source; declaring a different
`source_address` in a DoT probe does not change HTTP routing.

Required denial evidence is explicit 403 for HTTPS route ACLs and explicit DNS
REFUSED for DoT. A DoT denied probe queries both the fixture zone and an out-of-zone
recursive name. Firewall timeouts are evidence only for the separate plain-DNS
`firewall-denied` class. See [verify](../roles/verify/README.md).

## 10. Preflight from the controller

Check plaintext placeholders and local syntax without contacting hosts:

```bash
rg -n 'REPLACE_' inventories/site/hosts.yml \
  inventories/site/group_vars/microlab_management/main.yml
ansible-playbook -i inventories/site/hosts.yml playbooks/site.yml \
  --syntax-check --ask-vault-pass
ansible-playbook -i inventories/site/hosts.yml playbooks/site.yml \
  --list-hosts --ask-vault-pass
```

The `rg` command should have no matches (exit 1). Review Vault with
`ansible-vault edit` to remove its placeholders; never print decrypted inventory
with `ansible-inventory --list` or debug variables into a shared log.

Next, deliberately test management connectivity/sudo and unprivileged probe
connectivity (these commands contact hosts):

```bash
ansible -i inventories/site/hosts.yml microlab_management -m ping \
  --ask-vault-pass --ask-become-pass
ansible -i inventories/site/hosts.yml microlab_probes -m ping \
  --ask-vault-pass -e '{"ansible_become": false}'
```

Keep an out-of-band console available while first installing the firewall.
Syntax success is not a preflight of ports, state, API compatibility or packages.
Do not treat full-playbook `--check` as a guaranteed side-effect-free rehearsal:
some commands explicitly run even in check mode. Do not use `--diff` for a run
carrying secrets.

## 11. First run: reach DNS, CA and initial Caddy

```bash
ansible-playbook -i inventories/site/hosts.yml playbooks/site.yml \
  --ask-vault-pass --ask-become-pass
```

This performs real changes. With the intentionally empty TLS API token, the
expected bootstrap stop is the TLS role's protected-secret assertion, after
baseline, DNS, CA and initial Caddy succeed. **Any earlier failure is a separate
problem**; resolve it before continuing. There are no phase tags and no automatic
pause/resume workflow. Reruns repeat the ordered play.

Confirm the CA phase passed, then change site `main.yml` to:

```yaml
microlab_step_ca_initial_deploy: false
```

If initialization stopped with `ca.json` present but no durable database, do not
delete files or toggle flags until it passes. Use the explicit interrupted-state
procedure in [CA recovery](ca-recovery.md). A normal run requires valid deployed
material and Badger state.

## 12. Create the TLS API and enrollment tokens

Connect to Technitium through an SSH tunnel from the controller:

```bash
ssh -i /REPLACE_WITH_CONTROLLER_SSH_KEY -o ExitOnForwardFailure=yes \
  -N -L 127.0.0.1:15380:127.0.0.1:5380 \
  REPLACE_WITH_MANAGEMENT_SSH_USER@REPLACE_WITH_MANAGEMENT_IP
```

Plain `ssh` does not read Ansible's inventory key setting, so supply the same
private key explicitly with `-i`. Keep that process open in its terminal;
no shell prompt after connecting is expected with `-N`. Use a second controller
terminal, return to the checkout and activate `.venv` for Vault/Ansible commands.
In a browser on the same controller, open
`http://127.0.0.1:15380` and log in as `admin` with the vaulted password (it has
been rotated from the upstream default). In Administration, create a dedicated
renewal user/group with **Settings: View and Modify** and generate a named API
token for that user. Do not use a one-use API token: renewal needs persistent
API access. API tokens inherit their user's permissions; keep this account
restricted. The [Technitium API documentation](https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md#create-api-token)
also documents `/api/user/createToken` if your pinned UI differs.
UI labels can vary by release; this menu path has not been verified against
your pinned server. The required outcome is a persistent token belonging to a
user that can read and modify Settings, not a one-use session token.

Use `ansible-vault edit inventories/site/group_vars/microlab_management/vault.yml`
and fill `micolab_technitium_api_token`. The token will necessarily be stored in
the protected target renewal environment for unattended renewal.

On the **management host**, in an interactive SSH session:

```bash
sudo /usr/local/sbin/step-ca-technitium-token dns.microlab.hnh
```

Enter the **Technitium JWK provisioner password** from offline preparation when
prompted, not the CA intermediate password. Treat the printed short-lived token
as a secret; place it in Vault as `micolab_technitium_enrollment_token`. Run the
following controller command promptly: the token is single-use and expires in ten minutes,
and the earlier phases run again before TLS. If it expires before enrollment,
mint a fresh token and retry. Never put a token in `-e`, a URL or shell history.

```bash
# CONTROLLER, from repository root, with .venv activated
ansible-playbook -i inventories/site/hosts.yml playbooks/site.yml \
  --ask-vault-pass --ask-become-pass
```

The next run should enroll native DNS TLS, pass DoH readiness, install Forgejo,
and add its Caddy site. It will stop at final acceptance if Git inputs are empty,
or at an earlier real gate such as the documented 8053 bind check. Verify which
gate failed instead of assuming Forgejo was reached. Once enrollment succeeded,
clear `micolab_technitium_enrollment_token` back to `""` in Vault. Leave the API
token and PFX password intact; the systemd timer renews without the controller.

## 13. Prepare the disposable Forgejo repository and Git SSH identity

Ensure your workstation resolves `git.microlab.hnh` through Technitium and trusts
the pinned public root. Open `https://git.microlab.hnh/`, log in with the configured
Forgejo administrator, and create **private** repository
`microlab-admin/deployment-check`. Select initialization with a README so it has
an initial commit. This is a disposable acceptance repo: verify writes and
deletes uniquely named branches. Do not use a production repository or protect
the `microlab-verify-*` branches from deletion.

Create an HTTPS access token for that account with repository read/write access
to this repo. Set the following existing Vault keys:

```yaml
micolab_verify_git_https_username: microlab-admin
micolab_verify_git_https_token: "REPLACE_WITH_REPOSITORY_WRITE_TOKEN"
```

On the **management host**, create a dedicated test SSH key (not your personal
administrator key). Do this once, and keep its directory outside verify's
automatically removed `/var/lib/microlab/verify-git` workspace:

```bash
sudo install -d -m 0700 /root/microlab-acceptance
sudo ssh-keygen -t ed25519 -N '' \
  -f /root/microlab-acceptance/id_ed25519 \
  -C microlab-disposable-git-acceptance
sudo cat /root/microlab-acceptance/id_ed25519.pub
```

The empty passphrase permits the root-run, batch-mode acceptance probe. Restrict
this identity's repository access and keep the private key root-readable only.
Register the printed public key in that Forgejo account's **SSH keys** settings.
Do not manually append it to `/home/git/.ssh/authorized_keys`: Forgejo must create
the forced-command entry.
Registering a new key on the administrator account grants that account's access;
the key itself is not limited to the disposable repository. For a lasting test
identity, create a separate non-admin Forgejo user, grant it write access to
this repository, and use that user's token and registered key instead. Update
`micolab_verify_git_https_username` accordingly; the repository owner/path can
stay `microlab-admin/deployment-check`.

Build the pinned host-key entry from the target's own public host key, through
the already authenticated management SSH session:

```bash
# TARGET: fail if this SSH host-key type does not exist; select the actual
# configured public host key instead if your sshd uses a different type.
sudo sh -c 'awk "{print \"git.microlab.hnh \" \$1 \" \" \$2}" \
  /etc/ssh/ssh_host_ed25519_key.pub > /root/microlab-acceptance/known_hosts'
sudo chmod 0600 /root/microlab-acceptance/id_ed25519 \
  /root/microlab-acceptance/known_hosts
```

These paths are **on the target**, not the controller. Keep them for repeat
acceptance, or remove/revoke them afterward and restore test inputs when needed.
The role removes its temporary cloned repositories/askpass helper, not this
operator-supplied key. If using a different account/repo, update both
`micolab_verify_git_repo` in `main.yml` and the HTTPS user in Vault.
`/root/microlab-acceptance` is outside the default backup set: recreate the test
identity/host-key file after a restore before requesting full Git acceptance.

## 14. Complete acceptance, then run again

After all inputs are present, run from the controller:

```bash
ansible-playbook -i inventories/site/hosts.yml playbooks/site.yml \
  --ask-vault-pass --ask-become-pass
```

Record this run's time and final recap. **A failed run is failed acceptance even
if an old report says complete.** Reports are written at the end of their
phases; a failed rerun can leave previous reports in place. Inspect modification
times and verify's `generated_at` along with this run's result:

```bash
# TARGET
sudo cat /var/lib/microlab/dns-acceptance.json
sudo cat /var/lib/microlab/verify-acceptance.json
sudo stat -c '%y %n' /var/lib/microlab/dns-acceptance.json \
  /var/lib/microlab/verify-acceptance.json
sudo systemctl is-enabled technitium-tls-renew.timer
sudo systemctl is-active technitium-tls-renew.timer
sudo systemctl status technitium-tls-renew.timer --no-pager
sudo cat /var/lib/technitium-tls/status.json
```

The deployment needs both successful tasks and honest reports. Missing tests
or explicit overrides are incomplete acceptance. Keep
`micolab_dns_accept_unverified_external_acl`,
`micolab_verify_accept_unverified_external_acl`, and
`micolab_verify_accept_unexecuted_git_acceptance` false (their defaults).

Expected current-run values are:

- DNS: `external_acl_verified: true`, `external_acl_override: false`, and
  `unexecuted_gates: []`.
- Verify: `overall: complete`, `git.state: executed`,
  `external_acl.state: executed`, both overrides false, both Git cleanup fields
  `deleted`, and `credentials_removed`/`workspace_removed` true.
- Renewal timer: `enabled` and `active`. The oneshot renewal service can be
  inactive between timer firings; that alone is not an error.

Verify's `unexecuted` list still names reboot, offline ACME renewal and restore.
Its `complete` value covers the automated checks only; record those operational
tests separately. It is not a declaration that the machine has passed recovery.

Run site again and inspect changes. Deliberate acceptance activity, such as
temporary Git branches, may report changes; the requirement is no unintended
configuration changes, no replacement CA and no rotating durable secrets.
Reboot the host and repeat checks. With WAN disconnected and the internal time
source/CA running, verify local DNS, DoH/DoT, and actual certificate renewal.
The [certificate renewal](certificate-renewal.md) guide explains renewal windows,
publication retries and expired-leaf recovery. The helper has **no force-renew
flag**: a successful immediate run may keep a still-valid certificate. On the
target, these commands exercise validation and publication respectively:

```bash
sudo /usr/local/sbin/technitium-tls-renew \
  --config /etc/technitium-tls/renewal.env --check-only
sudo /usr/local/sbin/technitium-tls-renew \
  --config /etc/technitium-tls/renewal.env --publish-only
```

Neither command proves a new certificate was issued. Actual renewal acceptance
requires a renewal-window run and before/after live serial/fingerprint evidence;
forced replacement and failure injection need an isolated, reviewed test
procedure, which this guide does not supply. Do not delete a production leaf or
change the host clock to simulate it. Confirm trust
with actual client applications, not just command-line probes.

## 15. Make and rehearse a recoverable backup

On the **target**, create the configured destination outside all archived trees:

```bash
sudo install -d -m 0700 /srv/microlab-backups
```

Then, from the controller, deliberately request the service-quiescing backup:

```bash
ansible-playbook -i inventories/site/hosts.yml playbooks/backup.yml \
  --ask-vault-pass --ask-become-pass -e '{"micolab_backup_confirm": true}'
```

This briefly stops services and locks renewal while capturing consistent state.
The playbook prints its resulting paths. On the target you can list them with:

```bash
sudo ls -lt /srv/microlab-backups/
```

The archive prefix is **`micolab-backup-`** (the repository's spelling). Keep the
matching `.tar.gz`, checksum sidecar and manifest together; use the actual
emitted filename when restoring, not a guessed timestamp.
Backups contain private keys and application secrets. Replicate them off-host
with protected storage/encryption; a directory on the same SSD does not survive
SSD loss. Retain the controller inventory/Vault, its unlock method, pinned
artifacts and bootstrap repo separately. Root escrow remains separate from
ordinary host backups.

Rehearse restoration on an isolated host using [backup/restore](backup-restore.md),
including its isolated marker, exact confirmation phrase, archive checksum and
default stopped-service behavior. Do not point the restore playbook at the
production inventory as a test. Before upgrades, back up and preserve matching
binary/config/database versions; replacing a binary alone does not undo migrations.

## Troubleshooting checkpoints

| Where it stops | What to check/change |
| --- | --- |
| Baseline input validation | Actual OS/arch, real IPs/CIDRs, controller artifacts/hashes, fixture settings, future Git repo identity, NTP, dependencies and storage. |
| DNS remote probes | Actual bound source IPs, routes/NAT, unprivileged probe tooling, non-overlapping ACL classes; fixture zone must be owned by this deployment. |
| Resolver change | `/etc/resolv.conf` ownership/type and verified backup; never discard its rollback evidence. |
| CA source/preflight | Absolute controller files, correct DER fingerprint, intermediate password/key pair, and genuinely empty first target versus restored state. |
| CA-to-Caddy issuance | Target resolves service names locally, can reach its own Caddy port 80, exact `acme` provisioner and root trust. |
| TLS protected-secret gate | Persistent Settings token/PFX password; single-use enrollment token only for initial enrollment. |
| Native TLS validation | Correct server-only EKU, SAN/chain, pair consistency and actual live certificate; do not bypass verification. |
| Final loopback-8053 check | Known Technitium listener/verify compatibility issue; do not claim complete acceptance or hide the check. |
| External HTTP denied probe | Must reach Caddy and get 403; check the narrower DoH CIDRs and actual route-selected source. |
| Git clone/push/cleanup | Initialized disposable repo, visibility, write token, registered key, target-side pinned host keys and permission to delete test branches. |
| Backup prerequisite | TLS timer is actually deployed; effective certificate/key/env paths are included; destination exists outside source trees. |

For routine edits use `ansible-vault edit` for secrets and the site `main.yml`
for non-secrets, then rerun the same ordered site command. Keep deployment
evidence and acceptance reports privately; none of these site-specific files
belong in the public GitHub repository.
