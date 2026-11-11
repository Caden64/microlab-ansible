# step_ca

Experimental implementation; live deployment acceptance remains unexercised.
See [validation evidence and limits](../../docs/validation.md).

Deploys the MicroLab intermediate certificate authority on the dedicated
management host. The root CA is created and kept offline; this role deploys
only the public root, the offline-issued intermediate certificate, its encrypted
private key, its password, and the single `ca.json` configuration authority.

The role never runs `step ca init`, never generates CA key material, and fails
closed when state is missing or partial. See [CA recovery](../../docs/ca-recovery.md) for the
offline initialization and restore workflow.

## Network and naming

- step-ca listens only on `127.0.0.1:4443`.
- Its internal TLS certificate carries both `ca.microlab.hnh` and the
  `127.0.0.1` IP SAN.
- The CA is verified directly with the pinned public root, not through Caddy.
- Health and ACME directory gates use `curl --cacert` against both the loopback
  IP and the DNS name (resolved to loopback with `--resolve`).

## Required inventory inputs

Canonical CA variables use `microlab_`; selected existing shared `micolab_`
aliases are consumed where documented. Both spellings are part of the current
interface. Empty defaults require operator-supplied reviewed values.

| Variable | Required | Meaning |
| --- | --- | --- |
| `microlab_step_ca_version` | yes | Pinned step-ca release version (no `v` prefix). |
| `microlab_step_ca_checksums` | yes | Mapping `amd64`/`arm64` to the reviewed SHA-256 of the step-ca archive. |
| `microlab_step_cli_version` | yes | Pinned step CLI version. |
| `microlab_step_cli_checksums` | yes | Mapping `amd64`/`arm64` to the reviewed SHA-256 of the step CLI archive. |
| `microlab_step_ca_root_cert_src` | yes | Absolute controller path to the public root certificate. |
| `microlab_step_ca_root_fingerprint_sha256` | yes | Reviewed SHA-256 fingerprint, hex with or without colons. |
| `microlab_step_ca_intermediate_cert_src` | yes | Absolute controller path to the intermediate certificate. |
| `microlab_step_ca_intermediate_key_src` | yes | Absolute controller path to the encrypted intermediate key. |
| `microlab_step_ca_intermediate_key_password` | yes, vault | Password that decrypts the intermediate key. |
| `microlab_step_ca_technitium_jwk_key` | yes | Public JWK dict for the restricted Technitium provisioner. |
| `microlab_step_ca_technitium_jwk_encrypted_key` | yes, vault | `encryptedKey` string for that JWK provisioner. |
| `microlab_step_ca_initial_deploy` | first run | Must be `true` only for an explicit first deployment with complete, valid controller-side material, no valid CA database, and a target that is either empty or already holds the complete offline material. A partial target is never treated as a new CA. |
| `microlab_step_ca_recover_missing_config` | recovery | Must be `true` to re-render a missing `ca.json` only when complete regular material and a structurally valid badgerv2 CA database are present. It never creates, repairs, or replaces material or the database. |

Artifacts are read from `microlab_step_ca_artifact_base_url`, which must be a
`file:///` URL by default. `get_url` runs on the target, so this URL refers to
**target-local archives**, not the controller staging directory. Stage them on
the management host separately. Certificate/key `*_src` paths above remain
controller-local. The role also ensures four OS packages through `apt` with
`update_cache: false`; preinstall them or supply an offline package source.
Remote artifact URLs are rejected unless
`microlab_step_ca_allow_remote_artifacts: true` is explicitly reviewed.

## Key defaults

| Variable | Default |
| --- | --- |
| `microlab_step_ca_address` | `127.0.0.1:4443` |
| `microlab_step_ca_ca_url` | `https://127.0.0.1:4443` |
| `microlab_step_ca_dns_names` | `[ca.microlab.hnh, 127.0.0.1]` |
| `microlab_step_ca_caddy_provisioner_name` | `acme` |
| `microlab_step_ca_technitium_provisioner_name` | `microlab-technitium` |
| `microlab_step_ca_cert_lifetime` | `168h` |
| `microlab_step_ca_technitium_cert_names` | `[dns.microlab.hnh]` |
| `microlab_step_ca_allowed_dns_names` | `[*.microlab.hnh, microlab.hnh]` |
| `microlab_step_ca_allowed_ip_addresses` | `[127.0.0.1]` |
| `microlab_step_ca_install_public_trust` | `true` |
| `microlab_step_ca_root_cert_owner` / `microlab_step_ca_root_cert_group` | `root` / `root` (public root only; localhost tests override) |
| `microlab_step_ca_trust_store_path` | `/usr/local/share/ca-certificates/microlab-root.crt` (also consumes the existing `micolab_step_ca_trust_store_path` alias when set) |
| `microlab_step_ca_allow_renewal_after_expiry` | `false` (must remain false) |
| `microlab_step_ca_ipv6_enabled` | `false` |

## Provisioners

The role is the only provisioner authority. It renders one `ca.json`; do not use
`step ca provisioner` to mutate the live CA.

- `acme` — ACME, seven-day maximum/default lifetime, Caddy's dedicated
  provisioner. The name is part of the public interface and must remain exactly
  `acme`; the ACME directory is
  `https://127.0.0.1:4443/acme/acme/directory`.
- `microlab-technitium` — restricted JWK enrollment for Technitium, seven-day
  maximum/default lifetime, renewal after expiry disabled. The role attaches an
  explicit `options.x509.template` from
  `files/technitium-x509.template.json`, so the issued leaf carries exactly
  `serverAuth` instead of Smallstep's default `serverAuth` + `clientAuth`. The
  token helper `/usr/local/sbin/step-ca-technitium-token` only mints tokens for
  names in `/etc/step-ca/technitium-allowed-names`.

Self-hosted step-ca supports issuance policy only at the authority level, so the
Technitium name restriction is enforced at token minting plus the authority
policy, not by a per-provisioner policy. See
[certificate renewal](../../docs/certificate-renewal.md) for the honest limitation.

## Published integration interface

Other roles may consume these outputs. They are stable names from this role:

| Output | Value |
| --- | --- |
| CA direct API | `microlab_step_ca_ca_url` (`https://127.0.0.1:4443`) |
| CA public DNS name | `ca.microlab.hnh` |
| Public root on host | `{{ microlab_step_ca_certs_dir }}/root_ca.crt` |
| Intermediate on host | `{{ microlab_step_ca_certs_dir }}/intermediate_ca.crt` |
| Caddy ACME directory | `https://127.0.0.1:4443/acme/acme/directory` |
| Caddy provisioner | `acme` |
| Technitium provisioner | `microlab-technitium` |
| Technitium token helper | `/usr/local/sbin/step-ca-technitium-token` |
| Public trust bundle path | `microlab_step_ca_trust_store_path` |

Caddy requires the direct loopback directory above. A proxied CA URL is not
a supported issuer substitute; direct issuance avoids a dependency on the
frontend certificate it is obtaining.

## Database policy

The only supported backend is `badgerv2`. A database directory is durable state
only when it contains badgerv2 structure: a regular non-empty `MANIFEST` and at
least one regular non-empty numbered `.vlog` or `.sst` file. Additional regular
Badger side files such as `KEYREGISTRY` are accepted. Empty directories, empty
subdirectories, symlinks, zero-byte files, and arbitrary non-database files are
rejected rather than treated as a repaired database. Other backends require a
reviewed migration and are never selected implicitly.

This is a structural filename check. It rejects obvious junk and empty state; it
does not parse Badger internals or prove that the database will open. Restored
or questionable databases must be validated by starting a copy against the
restored tree or with Badger tooling. The test suite's Badger fixtures are
synthetic filenames, not a real Badger database.

## Safety gates

- Root fingerprint is checked before overwriting an existing root and again
  after deployment. Configuration-only recovery also re-reads and checks the
  existing root fingerprint before any CA state write.
- A `root_ca_key` at the documented secrets path aborts the role. A recursive
  filename scan of the target CA home also rejects `*root*key*` and
  `*root*private*` names (for example `root_ca_private.pem`) and refuses a
  symlinked or non-directory CA home. The scan is a best-effort heuristic: it
  cannot prove that no root key exists elsewhere or under an unrecognised name.
  Offline custody discipline remains the primary control.
- A normal run requires `ca.json`, all four durable material files as regular,
  non-empty, non-symlink files, and a structurally valid badgerv2 database.
- Controller-side sources are validated **on the Ansible controller**
  (`delegate_to: localhost`, `become: false`) because `copy: src=` reads the
  controller, never the target. This runs before `install.yml`, so an unusable
  source fails before any target package, binary, or CA state changes. Source
  paths must be absolute so validation and `copy` resolve the same file. Each
  host validates its own variables; there is no `run_once` across hosts. The
  controller needs the `openssl` CLI.
- Target state and already-deployed material are validated **on the target**,
  before `configure.yml` creates the CA user, directories, material, database,
  or `ca.json`. This is before any CA state mutation, but not before every
  target write: `install.yml` has already installed dependencies and staged the
  pinned binaries, because target OpenSSL and those binaries are prerequisites.
  The target is never asked to validate a controller-only source path, and the
  controller is never asked to validate target material.
- Configuration-only recovery (`microlab_step_ca_recover_missing_config`) is
  accepted only when `ca.json` is the sole missing piece: every durable material
  file and a structurally valid database must already exist and validate. It
  re-renders only the role-managed configuration; it never replaces material,
  repairs the database, or runs `step ca init`.
- First deployment (`microlab_step_ca_initial_deploy`) is separate: it requires
  complete, cryptographically valid controller sources, no valid database, and
  a target that is either genuinely empty or already contains the complete
  valid material. A partial target aborts.
- Missing, partial, invalid, ambiguous, or otherwise unexpected state aborts
  and directs the operator to restore the full `/etc/step-ca` tree from backup.
- Config is backed up by the `template` module on each change.
- `/health`, both TLS SAN paths, the ACME directory, and the exact live
  provisioner set are gated before the role reports success. The provisioner
  check unwraps the `{"provisioners": [...], "nextCursor": "..."}` response and
  requests the 100-entry cap; a non-empty `nextCursor` fails the gate instead
  of comparing an incomplete page.
- Service, trust, and systemd handlers are flushed before health gates.

## First-deployment crash window

`configure.yml` writes `ca.json` before `service.yml` starts step-ca, and
step-ca creates the badgerv2 database on its first start. A crash after
`ca.json` exists but before the database is created therefore leaves a tree the
role must not "fix" automatically. The next run fails closed: `ca.json` is
present but durable state is incomplete. Do not let this role create an empty
database, do not run `step ca init`, and do not delete an existing database.
The controlled recovery procedure is in [CA recovery](../../docs/ca-recovery.md); it requires
verifying that no database data ever existed and prefers restoring a full-tree
backup.

## Limitations

- The role intentionally does not initialize a CA. Offline initialization must
  happen on a trusted workstation and is documented in [CA recovery](../../docs/ca-recovery.md).
- No IPv6 SAN or policy entry is emitted unless `microlab_step_ca_ipv6_enabled`
  is explicitly true as part of a reviewed IPv6 design.
- The CA is a loopback backend. Publishing it through Caddy/TLS is another
  role's responsibility.
- The pinned versions and checksums are not guessed; the operator must supply
  them from reviewed release artifacts.
- The root-private-key scan of the target CA home is filename-based. It cannot
  detect a root key with an unexpected name, and it does not traverse symlinked
  subdirectories of the CA home.

## Test scope

- `tests/test_step_ca_preflight.py` runs the real preflight and first-deploy
  material include through `ansible-playbook` on one localhost. It covers the
  state matrix, OpenSSL validation, symlink/empty-file handling, and the
  badgerv2 structural policy. Controller and target share a filesystem, so it
  cannot detect controller/target confusion.
- `tests/test_step_ca_cross_host.py` runs the same task files with the
  controller on `connection: local` and the target in a test-only bubblewrap
  mount namespace where the controller source directory is masked or overlaid.
  It proves controller-only sources validate and deploy correctly, same-named
  target files cannot substitute their bytes, target-only root escrow files are
  found, target material validation stays on the target, relative source paths
  are rejected, and a direct target preflight without the controller source
  gate fails closed.
- Neither test executes the full `configure.yml` user/directory/config
  rendering, the systemd unit, the trust handler, or the service/health gates.
  Those remain deployment-gated by the role itself.
