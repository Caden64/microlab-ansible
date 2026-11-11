# Backup and restore

This is an operator procedure; live recovery has not been exercised. See
[validation evidence and limits](validation.md).

This procedure covers the MicroLab **management host**: Forgejo, step-ca, the
authoritative DNS/DNS-over-HTTPS backend, Caddy, and the Technitium TLS
renewal helper. It does not back up challenge workloads, the offline root
escrow, or anything not listed below.

The governing rule is: a backup is a copy of state while the services that own
that state are stopped and while the renewal writer is excluded. A live SQLite
copy, a live Git repository pack, a live CA database, or a TLS certificate set
being rewritten by the renewal helper is not accepted as a consistent backup.

## What is copied

| Component | Included state | Why |
| --- | --- | --- |
| Forgejo | `/var/lib/forgejo` (SQLite `forgejo.db`, `forgejo.db-wal`, `-shm`, repositories, LFS, attachments, avatars, archives, packages, queues, indexers, sessions) and `/etc/forgejo/app.ini` | Full application state plus durable secrets. |
| step-ca | `/etc/step-ca` (intermediate CA, database, config, issued certs) | Recover the issuing intermediate and CA configuration. |
| DNS | `/etc/dns` (Technitium settings, zones, credentials, `/etc/dns/tls` PFX/PEM/key/password) | Authoritative zone/config state and the currently published DoT material. Override if the site DNS role uses other paths. |
| Caddy | `/var/lib/caddy` (persistent certificate/account state) | Avoid unnecessary re-issuance and preserve ACME account state. The Caddyfile is code and is re-rendered by Ansible. |
| Technitium TLS renewal | `/etc/technitium-tls` (`renewal.env`: CA URL, CA root/chain paths, certificate/PFX paths, PFX password-file path, API token, renewal thresholds, lock/status paths) | Without the renewal environment, a restored host cannot renew DoT and cannot recover the API credential flow. The helper binary and systemd units are code and are reinstalled by `roles/technitium_tls`. |
| **Deliberately not copied** | `/var/lib/technitium-tls` runtime status and `renew.lock`; offline root escrow (`root_ca_key*`, `root_ca.key*`, `root_ca_private*`, `offline-root*`, `offline_root*`) | The lock inode must not be replaced while it is held. Runtime status is recreated. The root must remain offline and is never part of an online backup. |

The playbooks also check that the configured certificate, key, PFX, PFX
password, CA root, and CA chain paths are below an included/restored tree. If
you move those paths outside `/etc/dns` or `/etc/step-ca`, add their directory
to `micolab_backup_include_paths` and `micolab_restore_include_paths`; otherwise
the run fails closed rather than producing a backup that cannot renew.

The playbooks read the role-owned path interfaces rather than assuming fixed
paths: `micolab_forgejo_data_dir`, `micolab_forgejo_config_file`,
`micolab_forgejo_db_path`, `micolab_forgejo_repo_root`,
`micolab_caddy_state_dir`, `microlab_step_ca_home`, and the **canonical**
`microlab_technitium_*` renewal variables. Set those in the site inventory when
a role moves state; the backup/restore include and required-member lists follow
them automatically.

### Renewal interface precedence

Both playbooks load `playbooks/vars/technitium_tls_interface.yml`. That file
mirrors `roles/technitium_tls/defaults/main.yml` exactly; it is not a nicer or
backup-specific precedence. The resolved order is:

1. an explicitly set canonical `microlab_technitium_*` role value wins
   (`cert_dir`, `cert_path`, `key_path`, `pfx_path`, `pfx_password_file`,
   `pfx_password`, `config_dir`, CA root/chain, state directory/name,
   lock/status, renewal environment, helper path, and service/timer units);
2. otherwise the role consumes the **supported shared aliases** that the role
   defaults actually read: `micolab_technitium_tls_cert_path` (the PFX path),
   `micolab_technitium_tls_key_path`,
   `micolab_technitium_tls_cert_password`, and
   `micolab_technitium_config_dir`;
3. otherwise the actual role default derived below `cert_dir`.

The exact mixed result is deliberate. For example, with
`microlab_technitium_cert_dir=/srv/tls` plus the shared
`micolab_technitium_tls_cert_path=/etc/dns/tls/dns.pfx` and
`micolab_technitium_tls_key_path=/etc/dns/tls/dns.key`, the role publishes the
PEM at `/srv/tls/dns.crt` and the password file at `/srv/tls/pfx.pass`, but the
key and PFX remain `/etc/dns/tls/dns.key` and `/etc/dns/tls/dns.pfx`. The
backup and restore playbooks reproduce that exact split. They do not silently
move the key/PFX to `/srv/tls`; if those paths are outside the default archived
trees, add `/etc/dns/tls` and `/srv/tls` to the include/allowlist variables.

When `microlab_technitium_state_dir` is not set, the playbooks compute
`/var/lib/<microlab_technitium_state_directory_name>` and derive
`renew.lock` from it, so the backup/restore helper holds the **same inode** as
the renewal service. There is no backup- or restore-specific lock/state
override.

Aliases the role never consumes are rejected before any state is touched.
That includes `micolab_technitium_enabled`,
`micolab_technitium_state_directory_name`, `micolab_technitium_state_dir`,
`micolab_technitium_lock_file`, `micolab_technitium_status_file`,
`micolab_technitium_renewal_env_file`, `micolab_technitium_helper_path`,
`micolab_technitium_service_unit`, `micolab_technitium_timer_unit`,
`micolab_technitium_cert_dir`, `micolab_technitium_cert_path`,
`micolab_technitium_key_path`, `micolab_technitium_pfx_path`,
`micolab_technitium_pfx_password_file`, `micolab_technitium_ca_root_cert`, and
`micolab_technitium_ca_chain_cert`. Setting one would move or archive recovery
state while leaving the live renewal runtime where it was.

There is **no supported `enabled=false` bypass**. `playbooks/site.yml` includes
`roles/technitium_tls` unconditionally, and the role enables and starts the
renewal timer without consulting `microlab_technitium_enabled`. A mere
boolean, an inactive unit, or a missing timer is not proof that renewal is not
deployed. Both playbooks therefore always require the renewal environment,
certificate/key/PFX/password/CA material, and durable lock. Backup additionally
requires the live renewal timer to prove the writer is quiesced; restore stops
that timer when it is loaded and holds the same lock. Both fail closed if a
backup/restore-specific disable or override flag
(`micolab_backup_renewal_enabled`, `micolab_backup_require_renewal_timer`, the
`micolab_backup_renewal_*` path overrides, or their restore equivalents) is
set. Do not invent an enabled flag to skip these safeguards; if renewal is
genuinely absent, this backup/restore workflow is not safe for that host.

### Recovery helper installation

Both playbooks install the recovery helpers under the protected directory
`/usr/local/lib/microlab` and then invoke the **installed** path. The installed
names are `micolab_lock.py`, `micolab_archive_guard.py`,
`micolab_backup_capture.py`, and `micolab_restore_commit.py`; the restore
preflight guard is run directly from `playbooks/files/micolab_archive_guard.py`.
`micolab_backup_helper_dir` and `micolab_restore_helper_dir` exist so the
integration tests can exercise the same copy and invocation tasks in a
temporary root; production keeps the default protected directory.

The backup helper validates every archive member after creation. It requires
the mandatory Forgejo database and repository root, `app.ini`, Caddy state, CA
state, DNS state, and the renewal environment. If any mandatory member is
missing, or any documented offline-root escrow name is present, the archive is
rejected and removed.

### Root escrow variants

The forbidden check rejects **every** `root_ca_key*`, `root_ca.key*`, and
`root_ca_private*` variant (`root_ca_private`, `root_ca_private.pem`,
`root_ca_private-key`, and so on), plus `offline-root*` and `offline_root*`
names. The exclude list contains the same patterns, but exclusion is not
trusted on its own. After the services are stopped and the durable lock is held, the helper scans
the included trees for documented escrow names that are **not** excluded and
fails without creating an archive. The playbook's `always` block then restarts
the previously active services and restores the timer. After creation, the
completed archive is inspected again before it is accepted. A misconfigured include path therefore
cannot silently leak escrow material.

## Consistency procedure

`playbooks/backup.yml`:

1. Requires `micolab_backup_confirm=true` and an existing writable,
   non-world-writable `micolab_backup_destination` other than `/`.
2. Resolves the destination, archive, and every included tree with
   `realpath`. The canonical destination and archive must not equal or lie
   under any archived tree. This rejects a nested destination such as
   `/var/lib/forgejo/backups` and a destination reached through a symlink
   alias into archived state.
3. Checks that every configured service unit is loaded. If the site uses a
   different DNS/CA unit name (defaults are `dns` and `step-ca`), set
   `micolab_backup_services` explicitly; a misspelled unit fails instead of
   silently omitting state.
4. Reads the renewal timer unit and lock path from the actual
   `roles/technitium_tls` interface (`microlab_technitium_timer_unit`,
   `microlab_technitium_lock_file`, `microlab_technitium_renewal_env_file`,
   `microlab_technitium_state_dir`, and
   `microlab_technitium_state_directory_name`). There are no backup-specific
   overrides. The defaults are `technitium-tls-renew.timer`, the lock derived
   from `microlab_technitium_state_dir` (or
   `/var/lib/<microlab_technitium_state_directory_name>`), and
   `/etc/technitium-tls/renewal.env`. Unsupported aliases and disable flags
   fail before the destination is inspected.
5. Records which main services and the renewal timer were active and enabled,
   then stops them. The renewal timer is stopped **before** the durable lock is
   taken. Any in-flight manual or systemd renewal finishes first; the backup
   helper then acquires the same `flock` and holds it for the whole critical
   section (stop services, `sync`, create archive, validate members, write
   sidecar and manifest). The lock file is opened, never unlinked or recreated,
   so the inode stays stable for the renewal helper.
6. The helper stops only the main services that were active, runs `sync`, and
   creates the archive. It opens the archive with `O_CREAT|O_EXCL` and mode
   `0600` under `umask 077` before tar writes a byte, so there is no window in
   which a `0644` file contains secrets. A fail-closed error removes the
   partial archive, sidecar, and manifest. It never deletes a pre-existing
   file.
7. Determines SQLite WAL state **after** quiescing. If `forgejo.db-wal` exists
   after the service stop and `sync`, it is mandatory in the archive. If it is
   absent because SQLite performed a clean shutdown/checkpoint, that is
   accepted: a consistent clean database without a WAL is a valid backup.
8. Writes a `.sha256` sidecar and a `.manifest.json` (both `0600`) containing
   the archive hash, whether the WAL existed after quiesce, included/excluded
   paths, stopped services, and lock information.
9. In an `always` block, restarts only the main services that were active,
   restores the renewal timer's original enabled/active state on success
   **and** failure, waits for the services, and health-gates Forgejo and the
   public HTTPS git endpoint.

Example (the destination must already be mounted):

```bash
ansible-playbook -i inventories/<site>/hosts.yml playbooks/backup.yml \
  -e micolab_backup_confirm=true \
  -e micolab_backup_destination=/srv/microlab-backups
```

The archive is local to the target. Copy it to off-host/offline storage with
your approved transfer procedure; this repository does not implement remote
replication.

## Backup validation

A backup is usable only when all of these hold:

- the `.sha256` sidecar matches the archive;
- the manifest names the same archive and SHA-256;
- the archive is readable as a gzip tar;
- the archive contains `var/lib/forgejo/data/forgejo.db`,
  `var/lib/forgejo/data/forgejo-repositories/`, `etc/forgejo/app.ini`,
  `etc/step-ca/`, `var/lib/caddy/`, `etc/dns/`, `etc/technitium-tls/`, and
  `etc/technitium-tls/renewal.env`; it also contains the configured DNS
  certificate (`dns.crt`), private key (`dns.key`), PFX (`dns.pfx`), PFX
  password file (`pfx.pass`), CA root, and CA chain files (paths follow the
  role variables);
- the SQLite WAL is present when it existed **after** quiescing;
- no `root_ca_key*`, `root_ca.key*`, `root_ca_private*`,
  `offline-root*`, or `offline_root*` member is present;
- no member is an absolute path, contains `..`, or is an unsupported special
  file.

If the WAL was absent because SQLite had a clean shutdown, that is acceptable;
the check only requires the WAL when it existed after the services stopped.

## Restore safety model

`playbooks/restore.yml` is deliberately **not** an automatic failover or a
production operation. It is an isolated-target workflow:

- Default `micolab_restore_commit=false` performs only read-only validation and
  makes no changes. `--check` also makes no changes.
- Required phrase: `micolab_restore_confirm=RESTORE-ISOLATED-MICROLAB`.
- Required `micolab_restore_isolated=true`.
- Required operator-created marker:
  `/etc/microlab/isolated-restore-target`.
- Refuses any host in `micolab_production`.
- Requires an absolute archive path and an exact SHA-256. The archive must be
  a regular file that is not world-readable or world-writable because it
  contains secrets. The guard rechecks the hash and every member again inside
  the commit helper, so a file swapped between preflight and commit is rejected.
- Uses a canonical full allowlist: every member name **and** every symlink and
  hardlink target must resolve under one of the configured restore roots. The
  default roots are `/var/lib/forgejo`, `/etc/forgejo/app.ini`, `/etc/step-ca`,
  `/etc/dns`, `/var/lib/caddy`, and `/etc/technitium-tls`. An extra member such
  as `etc/cron.d/payload`, an absolute member, a `..` member, a link escape, a
  special file, or a member below a symlink ancestor is rejected before any
  service is stopped.
- Rejects documented offline root material, including `root_ca_private*`.
- Requires the mandatory files and directories with the expected member kind
  (for example `forgejo.db` must be a regular file, not a directory or link).
- Stops all configured services and leaves them stopped. The renewal timer is
  also stopped. The commit helper holds the same durable renewal `flock` used
  by the helper, so a manual or systemd renewal cannot rewrite `/etc/dns` while
  the archive is extracted or installed.
- Extracts into a timestamped root-only staging directory, not directly to
  `/`. It uses `--numeric-owner --acls --xattrs`, verifies the extracted tree,
  then moves existing state to a timestamped quarantine and installs only the
  allowlisted top-level paths.
- Refuses to put the archive, quarantine, staging directory, or renewal lock
  inside a restored tree. This prevents moving the archive while reading it and
  prevents replacing the held lock inode/directory.
- Preserves archived modes, ACLs, and xattrs. It never recursively chmods
  restored state. Ownership may optionally be normalized by user/group name
  afterward, without touching modes.
- Leaves services **and** the renewal timer stopped unless
  `micolab_restore_start_services=true`; starting the timer additionally needs
  `micolab_restore_start_renewal_timer=true`.

Example validation-only run on the isolated target:

```bash
ansible-playbook -i inventories/<isolated>/hosts.yml playbooks/restore.yml \
  -e micolab_restore_archive=/srv/microlab-backups/microlab-backup-<timestamp>.tar.gz \
  -e micolab_restore_checksum=<sha256> \
  -e micolab_restore_confirm=RESTORE-ISOLATED-MICROLAB \
  -e micolab_restore_isolated=true
```

Then, after reviewing the dry-run output, explicitly commit:

```bash
ansible-playbook ... -e micolab_restore_commit=true
```

Services and the renewal timer remain stopped by default. Start services only
after inspection:

```bash
ansible-playbook ... -e micolab_restore_commit=true \
  -e micolab_restore_start_services=true
```

Start the renewal timer only after the certificate, API credential, and DoT
health checks pass:

```bash
ansible-playbook ... -e micolab_restore_commit=true \
  -e micolab_restore_start_services=true \
  -e micolab_restore_start_renewal_timer=true
```

### Ownership notes

- Tar extraction uses `--numeric-owner --acls --xattrs`, so archived numeric
  ownership, individual modes, POSIX ACLs, and xattrs are restored.
- Optional ownership normalization sets Forgejo state to `git:git`, `app.ini`
  to `root:git`, Caddy state to `caddy:caddy`, and the top levels of
  `/etc/step-ca`, `/etc/dns`, and `/etc/technitium-tls` to their service users.
  It does **not** pass a recursive `mode`, so a `0640` file, a `0600` private
  key, a `0750` directory, and ACL entries are not flattened to one mode.
- Recreate service users with matching UIDs when the archive's numeric owners
  must be preserved exactly. Disable normalization with
  `micolab_restore_apply_ownership=false` when numeric ownership is already
  correct.
- `/home/git/.ssh/authorized_keys` is intentionally not backed up as
  authoritative state. After a started restore, the playbook runs
  `forgejo admin regenerate keys`; the database is authoritative.

### Configuration is code

The Caddyfile, systemd units, firewall, DNS role settings, and the
`technitium-tls-renew` helper are re-rendered by the site roles. The backup
contains their durable state, not the code. After restore, reapply matching configuration on the isolated target through
reviewed role runs. A full site run starts services as it proceeds; it is not
a configuration-only restore step and does not preserve the stopped state.
Inspect the restored data and rollback kit before choosing that step. Do not
hand-edit restored config.

## Pre-upgrade backup and rollback

A pre-upgrade backup must be a consistent, quiesced backup, not an ad-hoc copy
of a running service. Before changing a Forgejo, step-ca, Technitium, Caddy, or
helper version:

1. Record the exact currently deployed binary versions, checksums, package
   versions, configuration file hashes, and the current backup manifest.
2. Run `playbooks/backup.yml` with the normal confirmation and destination.
   Verify the sidecar, manifest, required members, WAL decision, and (for
   Forgejo) `PRAGMA integrity_check` on a copy of the extracted database.
3. Keep that pre-upgrade archive together with the **matching** pre-upgrade
   binary, configuration, helper, and systemd unit set. A database or
   repository archive alone is not a rollback kit. The matching binary,
   matching configuration, and matching data must be restored together.

Forgejo and step-ca schema migrations are forward-only in normal operation. If
an upgrade has already migrated the database, do not expect an older binary to
open the newer schema. Restore the pre-upgrade archive's data **together with
the matching pre-upgrade binary and configuration**, on an isolated host. A
binary downgrade alone is not enough and may fail or corrupt state. If the
upgrade is being evaluated, take a second post-upgrade backup only after the
new version passes its acceptance checks.

Perform an isolated rollback rehearsal before relying on this procedure:

1. Build or restore a disposable isolated target with the same OS and service
   users.
2. Restore the pre-upgrade archive with `playbooks/restore.yml`.
3. Install the matching pre-upgrade binaries/configuration from the rollback
   kit, start the services only when ready, and run the acceptance checks
   below.
4. Record the result. An unexecuted rehearsal is a known gap, not a pass.

## Post-restore acceptance

Run these on the isolated target after starting services. Record each result;
do not treat an unrun test as a pass.

### Executable now

- [ ] Archive checksum and manifest match.
- [ ] The restore helper's staging directory was removed; the quarantine
      directory contains the previous state.
- [ ] All services start and `roles/verify` passes DNS A/NS, no-implicit-AAAA,
      DoH, DoT, Git HTTPS, loopback binds, and systemd enablement.
- [ ] Forgejo admin login works, the admin account is not forced to change
      password unexpectedly, and a test repository clone/push works. The
      inventory admin password must match the restored database or the role's
      basic-auth gate fails closed.
- [ ] LFS upload/download works for a test repository.
- [ ] Git over system SSH port 22 works with a Forgejo user key and the forced
      command; `authorized_keys` contains only Forgejo `command="..."`
      entries.
- [ ] `ca.microlab.hnh` serves the CA and the ACME directory is reachable with
      step-ca root validation.
- [ ] `dns.microlab.hnh/dns-query` returns the expected A answer and
      `dns.microlab.hnh:853` answers over validated DoT.
- [ ] Caddy serves a valid certificate for each enabled host from the step-ca
      root, not Caddy's local issuer.
- [ ] SQLite integrity check succeeds:
      `sqlite3 /var/lib/forgejo/data/forgejo.db 'PRAGMA integrity_check;'`
      (install the sqlite3 client on the isolated target first if needed).
- [ ] `technitium-tls-renew --check-only` succeeds with the restored
      `/etc/technitium-tls/renewal.env` after the helper and units are
      reinstalled by the role.
- [ ] Individual modes, ACLs, and xattrs on restored private keys and
      configuration match the archive; no recursive `0750` flattening occurred.

### Unexecuted by these playbooks

These are acceptance tests, not automatic checks. They must be performed and
recorded separately:

- **Reboot persistence**: reboot the isolated target, confirm Caddy, Forgejo,
  step-ca, and DNS come back, and rerun `roles/verify`. A static
  `systemctl is-enabled` check is not a reboot.
- **Offline ACME renewal**: disconnect WAN access, keep the local step-ca
  running, and exercise the renewal window. Confirm Caddy renews from that CA
  with TLS verification. A stopped CA cannot issue; test outage failure/retry
  and recovery separately. These isolated-target tests are not run by the
  playbooks.
- **Renewal-lock exclusion**: while a manual `technitium-tls-renew` run holds
  `/var/lib/technitium-tls/renew.lock`, confirm a backup waits for it and then
  completes, and confirm the lock inode is unchanged. This is a unit-tested
  helper behavior, not a live service test performed here.
- **External ACL probes**: from a host outside each configured CIDR, confirm:
  - `https://ca.microlab.hnh/` returns 403 outside management CIDRs;
  - `/dns-query` returns 403 outside DNS-client CIDRs and an answer from
    inside;
  - `/-/admin` returns 403 outside admin CIDRs and reaches Forgejo from
    inside;
  - ports 3000 (Forgejo), 4443 (step-ca), 8053 (Technitium DoH backend), and
    2019 (Caddy admin) are unreachable from every remote network (loopback
    only);
  - 853/tcp (DoT) is reachable only from admin, client, and
    `micolab_dns_authoritative_only_cidrs`; the authoritative-only source gets
    REFUSED for recursion, and none of those ports is open to an arbitrary
    external network;
  - plain 53 is reachable only from those same DNS networks, and 80/443 only
    from admin and client networks;
  - SSH 22 is reachable only from approved administration networks.
- **Restore acceptance itself**: prove the archive restores to a clean
  isolated target, then repeat the executable checks. The playbook can restore
  files, but it cannot prove the business acceptance criteria.
- **Rollback rehearsal**: perform the pre-upgrade rollback rehearsal above and
  record it. The repository does not run it.

## Recovery objectives and retention

No RPO/RTO values are invented here. Record the approved values in the site
runbook. The practical RPO is the last successful quiesced backup; the RTO is
dominated by transferring the archive, rebuilding the isolated target,
restoring state, reinstalling matching binaries/configuration, and completing
the acceptance checklist.

Retain at least the current and previous verified archives off-host, with the
manifest and checksum sidecar, plus the matching rollback kit for each
pre-upgrade archive. Never store the offline root escrow with the online
backups.

## Known gaps

- Backup destination replication and encryption at rest are external to this
  repository.
- The site DNS/CA service unit names, renewal timer, lock path, and state paths
  must match the role defaults or be supplied through the canonical
  `microlab_technitium_*` role variables (or the supported shared TLS aliases).
  This workflow has no supported disabled-TLS mode and no playbook-specific
  renewal overrides.
- A restore does not regenerate the Caddyfile, systemd units, firewall, or the
  renewal helper; the site roles must run.
- 2FA secrets, webhook credentials, and other values encrypted with
  `SECRET_KEY` are recoverable only if the supplied `app.ini` secret is
  restored unchanged.
- The playbooks do not perform a real reboot, offline renewal, external ACL
  probe, live restore, or live rollback rehearsal; those remain explicit
  operator acceptance steps.
- The helper tests use dummy archives, fake `systemctl` executables, and
  temporary filesystems. They do not prove a real service restart, a real
  SQLite recovery, or live health.
