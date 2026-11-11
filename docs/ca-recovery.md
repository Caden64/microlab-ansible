# MicroLab CA recovery

This is an operator procedure; live recovery has not been exercised. See
[validation evidence and limits](validation.md).

This document covers the offline root initialization workflow and recovery of
the MicroLab step-ca intermediate authority. The Ansible role in
`roles/step_ca` is a deployment and verification role only. It never runs
`step ca init`, never creates a root or intermediate key, and never treats a
missing `ca.json` as permission to make a new CA.

## Trust model and host contents

- The root CA is created and kept offline. Its private key must never be copied
  to the management host, Ansible controller, artifact store, or a backup that
  is stored with the intermediate material.
- The management host receives only:
  - the public root certificate;
  - the offline-issued intermediate certificate;
  - the encrypted intermediate private key;
  - the password that decrypts that key;
  - the role-managed `ca.json`;
  - the CA database directory.
- The deployed root is pinned by SHA-256 fingerprint. A mismatch is a hard stop.
- The role rejects the documented `secrets/root_ca_key` path and scans the CA
  home for known root escrow names: `root_ca_key*`, `root_ca_private*`, and the
  broader `*root*key*` / `*root*private*` patterns. This is a best-effort
  filename check, not a content scanner; it is not proof that no root key is
  hidden under another name or outside the CA home.
- step-ca listens on `127.0.0.1:4443` and presents both `ca.microlab.hnh` and
  `127.0.0.1` (IP SAN). No IPv6 SAN is emitted unless IPv6 is explicitly
  designed and enabled.

The management host is separate from challenge workloads. All loopback services
(step-ca, Technitium backends, Forgejo, and Caddy) share that host;
native DoT also listens on host interfaces behind the firewall. Inventory
must reach the management host by its SSH IP address, not by a DNS name, so
that a DNS outage cannot lock out the deployment path. The `hnh` zone is
expected to publish `ns1.microlab.hnh` and the `ca`, `dns`, and `git` A records;
no AAAA record is published unless IPv6 support is explicitly designed and
enabled in the DNS role.

## One-time offline initialization

Run this on a trusted, offline or access-controlled administration workstation.
Do not run it on the management host.

1. Obtain the pinned step CLI artifact through the reviewed offline process and
   verify its SHA-256 against the value recorded in inventory. Never use an
   unpinned download.

2. Create the root and intermediate with an offline root key. Use an explicit
   password file that stays in the offline environment.

   ```sh
   step ca init \
     --name "MicroLab Intermediate CA" \
     --dns ca.microlab.hnh \
     --dns 127.0.0.1 \
     --address 127.0.0.1:4443 \
     --password-file ./intermediate-password.txt \
     --provisioner admin \
     --provisioner-password-file ./admin-provisioner-password.txt
   ```

   `step ca init` creates the root private key in the offline step path. Keep it
   there or move it to the approved offline HSM/encrypted custody. It is not an
   input to this repository.

3. Record the public root SHA-256 fingerprint in the reviewed inventory:

   ```sh
   step certificate fingerprint "$(step path)/certs/root_ca.crt"
   ```

   The role accepts the fingerprint as lowercase/uppercase hex with or without
   colons, but requires exactly 32 bytes.

4. Create the provisioners that the role will render. The role remains the
   single configuration authority; these commands are used only to produce the
   initial key material, not to mutate the live CA.

   ```sh
   # Caddy's dedicated ACME provisioner. The name must be exactly "acme":
   # Caddy uses https://127.0.0.1:4443/acme/acme/directory.
   step ca provisioner add acme --type ACME \
     --x509-min-dur 5m --x509-max-dur 168h --x509-default-dur 168h

   # Restricted Technitium enrollment provisioner. The role supplies an
   # explicit x509 template below so this leaf is serverAuth-only.
   step ca provisioner add microlab-technitium --type JWK --create \
     --x509-min-dur 5m --x509-max-dur 168h --x509-default-dur 168h
   ```

   For the JWK provisioner, extract its public `key` object and its
   `encryptedKey` string from the offline `ca.json` (or from
   `step ca provisioner list`) into encrypted inventory as
   `microlab_step_ca_technitium_jwk_key` and
   `microlab_step_ca_technitium_jwk_encrypted_key`. The provisioner password is
   not deployed; it is supplied interactively when minting a Technitium token
   on the CA host.

5. Stage the certificate/key sources in a protected **controller-local**
   directory; their `*_src` variables are read and checked on the controller.
   Stage the binary archives separately on the **management host** for
   `microlab_step_ca_artifact_base_url` (default `file:///srv/microlab/artifacts`).
   The archive `get_url` tasks run on the target. Required material:

   - `root_ca.crt` (public only)
   - `intermediate_ca.crt`
   - `intermediate_ca_key` (encrypted with the intermediate password)
   - the intermediate password
   - pinned step-ca and step CLI archives with reviewed checksums for `amd64`
     and `arm64`

   Do not stage `root_ca_key`, a decrypted intermediate key, a root password, or
   a provisioner password file.

6. Set `microlab_step_ca_initial_deploy: true` for the first deployment only.
   The role copies the already-created material and renders `ca.json`; it does
   not create a CA. Remove the flag after successful CA initialization, even
   if a later site phase fails. Before the TLS phase, mint its enrollment token
   with the installed helper and supply a Technitium API token; see
   [staged bootstrap](../README.md#deployment-order-and-first-bootstrap).

## Normal redeploy

A normal run requires:

- `ca.json`, the public root, the intermediate certificate, the encrypted
  intermediate key, and the password file to be regular, non-empty,
  non-symlink files;
- the database directory to contain actual badgerv2 structure: a regular
  non-empty `MANIFEST` plus at least one regular non-empty numbered `.vlog` or
  `.sst` file (an empty directory, empty subdirectory, or arbitrary file is not
  durable data);
- the deployed root to match the pinned fingerprint;
- no root private key material: the documented `secrets/root_ca_key` path must
  be absent, and a recursive filename scan of the target CA home must find no
  `*root*key*` or `*root*private*` name. The scan is a best-effort heuristic and
  is not proof that no unrecognised root key exists elsewhere;
- the CA to answer `/health` with the pinned root over both the loopback IP and
  `ca.microlab.hnh`;
- the Caddy ACME directory to expose `newNonce`, `newAccount`, and `newOrder`;
- exactly the managed provisioner names to be live.

Any deviation aborts before the role reports success. The only supported
database backend is `badgerv2`; selecting another backend is rejected rather
than silently creating a new database.

The badgerv2 check is structural: it requires the expected filenames and
regular non-empty entries. It does not parse Badger internals or prove the
database will open. Restored or suspect database directories must be validated
against a running copy or with Badger tooling before they are trusted. The
repository's tests build synthetic Badger-shaped filenames; they establish the
rejection shape, not real database validity.

## Controller source preflight

An explicit first deployment (`microlab_step_ca_initial_deploy: true`) is
allowed on a genuinely empty target, but only after the controller-side root
certificate, intermediate certificate, and encrypted intermediate key have been
checked as regular non-empty files, the source root matches the pinned
fingerprint, the source intermediate chains to it, and the password decrypts the
source key and matches the certificate.

Those checks run **on the Ansible controller**, with `delegate_to: localhost`
and `become: false`, because `ansible.builtin.copy: src=` later reads the
controller, never the target. If the same tasks ran on the target, a
controller-only source would appear missing, and a same-named file already on
the target could be validated instead of the bytes that would actually be
deployed. The source paths must be absolute so the validated path and `copy`'s
resolved path are identical; relative paths are rejected. Each host in a play
validates its own source variables with no `run_once` across hosts, and the
controller needs the `openssl` CLI.

This controller gate runs before `install.yml`, so a bad source fails before any
target package, binary, or CA state change. The target's own state and
already-deployed material are validated separately on the target, before
`configure.yml` writes the CA user, directories, material, database, or
`ca.json`. That target preflight is after `install.yml` (which installs OpenSSL
and stages the pinned binaries), so it is before any CA state mutation, not
before every target write. The source preflight is also separate from target
state classification: a partial target still fails instead of being combined
with the sources to make a new CA.

## First deployment interrupted before the database exists

`configure.yml` writes `ca.json` before `service.yml` starts step-ca, and
step-ca creates the badgerv2 database on its first start. If the run is
interrupted after `ca.json` is written but before the database is created, a
later run sees `ca.json` without a database and aborts. That is fail-closed
behaviour, not permission to create a new database or CA.

Recover deliberately:

1. Stop step-ca and prevent further writes. Do not run `step ca init` and do not
   run the role repeatedly.
2. Preserve the whole `/etc/step-ca` tree in an access-controlled location for
   inspection.
3. Confirm this really is the interrupted first deployment: the database
   directory is absent or contains no entries at all (`find
   /etc/step-ca/db -mindepth 1` is empty), no certificate was issued, and the
   deployed material still matches the offline sources and pinned root
   fingerprint. If any database entry or issuance evidence exists, this is not
   the crash window — stop and restore the full tree from backup.
4. Prefer restoring the complete `/etc/step-ca` tree from a verified backup,
   then run the role normally.
5. Only when no backup exists and step 3 is positively confirmed may you move
   the role-rendered `ca.json` aside (leaving the empty database directory
   untouched) and re-run with `microlab_step_ca_initial_deploy: true`. The role
   re-validates the controller sources, re-renders `ca.json`, and step-ca then
   creates the database. Never delete a non-empty database, never regenerate
   the intermediate, and never use configuration-only recovery to manufacture
   an empty database.
6. Verify the health, TLS SAN, ACME directory, and provisioner gates after the
   recovery run.

## Recovery matrix

| Symptom | Action |
| --- | --- |
| `ca.json` missing, all CA material regular/non-empty and a structurally valid badgerv2 DB intact | Prefer restoring `ca.json` from backup. If no backup exists, set `microlab_step_ca_recover_missing_config: true` only after verifying the root fingerprint and the complete material; the role re-renders only `ca.json` and deliberately refuses to replace/repair material or create an empty database. |
| `ca.json` and any CA material, or the DB, missing/empty/symlinked (including an empty DB subdirectory) | Hard stop. Restore the whole `/etc/step-ca` tree from a verified backup. Do not initialize a replacement CA, do not regenerate the intermediate, and do not use configuration-only recovery to create or repair an empty database. |
| First deployment of already-initialized offline material | Set `microlab_step_ca_initial_deploy: true` only when `ca.json` is absent, the controller sources are complete and valid, no valid CA database exists, and the target is empty or already holds the complete offline material. A partial target is not a first deployment. |
| Root fingerprint mismatch | Hard stop. Restore the root that matches the pin. Changing the pin requires an explicit security review and re-enrollment of all consumers; it is not an Ansible convenience toggle. |
| Intermediate key/password mismatch | Hard stop. Restore the matching encrypted key and password from offline custody. The role verifies decryption and the public-key match before starting the CA. |
| Root private key found at `secrets/root_ca_key`, or any `*root*key*` / `*root*private*` filename under the CA home | Remove it immediately after securing offline custody. Treat the host as potentially compromised until reviewed; the role refuses to continue while it exists. The filename scan is best-effort and does not prove that no unrecognised root key exists elsewhere. |
| First deployment interrupted after `ca.json` but before step-ca created the database | Fail closed. Stop, preserve the tree, confirm the database has no entries and no issuance occurred, then prefer a full-tree restore. If no backup exists, follow the controlled rebootstrap procedure above; never create an empty database or a replacement CA. |
| Database lost or corrupt | Restore the DB backup. A fresh DB lets the same intermediate issue certificates, but ACME accounts and revocation history are lost. Do not run `step ca init`. |
| Enabled provisioner set differs from `ca.json` | The role's health gate fails. Do not use `step ca provisioner` to patch it; restore the role-managed configuration and restart. |
| Root key compromised | Out of scope for this role: stop issuance, perform a root rollover, redistribute the new public root, and re-enroll every consumer. |

## Backups

Back up, encrypted and access-controlled:

- `/etc/step-ca/config` (`ca.json`)
- `/etc/step-ca/certs`
- `/etc/step-ca/secrets` (encrypted intermediate key and password)
- `/etc/step-ca/db`

Keep the root private key in a separate offline custody location and backup
process. A backup containing both the root key and the intermediate key removes
the offline-root security property.

## Verification commands

```sh
# Pinned root fingerprint as deployed.
openssl x509 -in /etc/step-ca/certs/root_ca.crt \
  -noout -fingerprint -sha256

# Direct CA health with the pinned root over the IP SAN.
curl --fail --silent --show-error \
  --cacert /etc/step-ca/certs/root_ca.crt \
  https://127.0.0.1:4443/health

# DNS SAN path, without depending on the zone resolver.
curl --fail --silent --show-error \
  --cacert /etc/step-ca/certs/root_ca.crt \
  --resolve ca.microlab.hnh:4443:127.0.0.1 \
  https://ca.microlab.hnh:4443/health

# Provisioner set. The API wraps the list in an object and returns at most 100
# entries per page; the role requires an empty nextCursor before comparing.
curl --fail --silent --show-error \
  --cacert /etc/step-ca/certs/root_ca.crt \
  'https://127.0.0.1:4443/provisioners?limit=100'
```

If any command fails, stop and follow the recovery matrix. Do not delete
`ca.json`, the database, or the intermediate material to "start clean".

## Upstream references checked

- step-ca configuration, root/intermediate/key fields, and `dnsNames`:
  <https://smallstep.com/docs/step-ca/configuration/>
- step-ca provisioner management and JWK/ACME configuration:
  <https://smallstep.com/docs/step-ca/provisioners/>
- step certificate fingerprint and CA initialization workflows:
  <https://smallstep.com/docs/step-cli/reference/ca/init/> and
  <https://smallstep.com/docs/step-cli/reference/certificate/fingerprint/>
