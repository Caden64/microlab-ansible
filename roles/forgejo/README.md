# Role: `forgejo`

Experimental implementation; live deployment acceptance remains unexercised.
See [validation evidence and limits](../../docs/validation.md).

Pinned, official-architecture Forgejo on the MicroLab management host. The
service is a native systemd unit, binds only `127.0.0.1:3000`, uses SQLite with
WAL and a 60000 ms busy timeout, and is exposed by `roles/caddy` at
`https://git.microlab.hnh/`.

## What it enforces

- Official Forgejo release binary from an offline, SHA-256-pinned artifact.
- Dedicated `git` system user with a usable `/bin/bash` shell and locked
  password; native systemd service running as `git`.
- Local SSD-backed state; the role fails if the data filesystem is network or
  unsupported. It verifies the mounted filesystem type/source, not physical
  rotational media; the host/storage provider owns that guarantee.
- Full `app.ini` with a durable supplied `SECRET_KEY`, `INTERNAL_TOKEN`,
  OAuth2 `JWT_SECRET`, and LFS JWT secret. No generated/default secrets.
- `ROOT_URL=https://git.microlab.hnh/`, loopback HTTP, `INSTALL_LOCK=true`,
  registration disabled, Actions disabled globally and as a repo unit.
- SQLite database at `/var/lib/forgejo/data/forgejo.db`, WAL journal mode,
  `SQLITE_TIMEOUT=60000`.
- System OpenSSH on port 22 (never the built-in SSH server); Forgejo owns the
  git user's `authorized_keys` entries. The role validates that every line has
  a Forgejo `command="..."` forced command and that the file is git-owned 0600.
- A guarded, one-time admin bootstrap marker, an admin account with a supplied
  password, `must-change-password` unset, and a basic-auth `/api/v1/user` gate
  proving the account is usable.
- `REVERSE_PROXY_TRUSTED_PROXIES=127.0.0.1/32,::1/128` only. Caddy overwrites
  `X-Real-IP` and `X-Forwarded-For`, so a remote client cannot spoof its
  address into Forgejo through the proxy.
- Health gate at `/api/healthz`; the Caddy git site must not be enabled until
  this passes.
- The verify role performs real HTTPS and SSH clone/push acceptance against a
  disposable test repository and removes the unique test branches afterwards.
  The Forgejo role deliberately does not add an operator SSH key; register the
  acceptance key through Forgejo first.

## Required variables

| Variable | Description |
| --- | --- |
| `micolab_forgejo_version` | Exact release without a leading `v`. |
| `micolab_forgejo_checksums` | Map with `amd64` and/or `arm64` keys to 64-hex SHA-256 digests of official release binaries. |
| `micolab_forgejo_artifact_src_amd64` | Controller path to the staged `forgejo-<version>-linux-amd64` binary. |
| `micolab_forgejo_artifact_src_arm64` | Controller path to the staged `forgejo-<version>-linux-arm64` binary. |
| `micolab_forgejo_secret_key` | Durable Forgejo `SECRET_KEY` (32+ base64-style characters). |
| `micolab_forgejo_internal_token` | Durable `INTERNAL_TOKEN` (32+ base64-style characters). |
| `micolab_forgejo_jwt_secret` | Durable OAuth2 `JWT_SECRET` (32+ base64-style characters). |
| `micolab_forgejo_lfs_jwt_secret` | Durable LFS JWT secret (32+ base64-style characters). |
| `micolab_forgejo_admin_username` | Admin login, `[A-Za-z0-9_.-]+`. |
| `micolab_forgejo_admin_email` | Admin email address. |
| `micolab_forgejo_admin_password` | Admin password, at least 16 characters by default. |

Secrets must be supplied from a vault or external secret source. The role does
not generate them. If `micolab_forgejo_version` is empty and
`micolab_staged_artifacts` contains a matching `forgejo` entry, the role adopts
that version, SHA-256, and controller path. If no staged entry exists and
`micolab_forgejo_allow_online_download` is true, the official release URL is
used with the same checksum; offline staging is the default.

## Optional variables

| Variable | Default | Description |
| --- | --- | --- |
| `micolab_forgejo_staged_artifact_name` | `forgejo` | Name in the shared `micolab_staged_artifacts` list, used only when explicit pins are empty. |
| `micolab_forgejo_domain` | `git.microlab.hnh` | Public domain. |
| `micolab_forgejo_root_url` | `https://git.microlab.hnh/` | Exact public root URL, with trailing slash. |
| `micolab_forgejo_http_addr` | `127.0.0.1` | Loopback only. |
| `micolab_forgejo_http_port` | `3000` | HTTP port. |
| `micolab_forgejo_ssh_domain` | `git.microlab.hnh` | SSH clone domain. |
| `micolab_forgejo_ssh_port` | `22` | Must remain the system OpenSSH port. |
| `micolab_forgejo_data_dir` | `/var/lib/forgejo` | State root. |
| `micolab_forgejo_db_path` | `/var/lib/forgejo/data/forgejo.db` | SQLite database. |
| `micolab_forgejo_required_local_filesystems` | `[ext4, xfs, btrfs, f2fs]` | Fail-closed local SSD check. |
| `micolab_forgejo_manage_sshd` | `true` | Install the git-user sshd drop-in. |
| `micolab_forgejo_sshd_service` | `ssh` | Debian OpenSSH unit name. |
| `micolab_forgejo_sshd_dropin` | `/etc/ssh/sshd_config.d/90-microlab-forgejo.conf` | sshd drop-in path. |
| `micolab_forgejo_bootstrap_marker` | `/var/lib/forgejo/.microlab-admin-bootstrapped` | One-time admin bootstrap guard. |
| `micolab_forgejo_health_url` | `http://127.0.0.1:3000/api/healthz` | Health gate used before the Caddy git site. |
| `micolab_forgejo_install_lock` | `true` | Must remain true. |
| `micolab_forgejo_disable_registration` | `true` | Must remain true. |
| `micolab_forgejo_actions_enabled` | `false` | Must remain false. |
| `micolab_forgejo_lfs_enabled` | `true` | LFS enabled. |
| `micolab_forgejo_upload_max_mb` | `512` | Web upload limit. |
| `micolab_forgejo_attachment_max_mb` | `512` | Attachment limit. |
| `micolab_forgejo_upload_max_files` | `20` | Files per upload. |

## Admin bootstrap

The admin script runs only when `micolab_forgejo_bootstrap_marker` is absent.
It creates the admin if needed, unsets `must-change-password`, and writes the
marker as the `git` user. If the account is removed later while the marker
remains, the basic-auth gate fails; remove the marker deliberately to
re-bootstrap. The password is never logged (`no_log: true`).

## SSH details

- `START_SSH_SERVER=false`; system OpenSSH on port 22.
- `authorized_keys` is regenerated by `forgejo admin regenerate keys` and must
  contain only Forgejo forced-command entries.
- The drop-in adds `AcceptEnv GIT_PROTOCOL` and disables forwarding/TTY for the
  `git` user. It does not change the port.
- The role does not add an operator SSH key. Add user keys through Forgejo.

## Dependencies and ordering

Run this role with `become: true`; it creates the `git` system user, installs the binary, and manages systemd/sshd.

Target must provide Debian 12/13, systemd, Python 3, `git`, `git-lfs`,
OpenSSH on port 22, `findmnt`, `awk`, and `grep`. The CA/DNS loopback services
precede Forgejo in `playbooks/site.yml`, including the CA+DNS Caddy pass and
DoH readiness. The final Caddy Git site is enabled after Forgejo health passes.
The role creates the admin account, but not the acceptance repository or its
SSH credentials. Create a disposable repository with an initial commit and
register an acceptance user key through Forgejo before rerunning verify; see
[first bootstrap](../../README.md#deployment-order-and-first-bootstrap).
