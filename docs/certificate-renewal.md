# MicroLab certificate renewal

MicroLab uses a seven-day (`168h`) certificate lifetime with early renewal and
an expiration alert. Renewal is local, serialized, and independent of the
Ansible controller. There is no controller-side certificate authority, no
renewal network call from the controller to the CA, and no renewal after expiry.
This describes the implemented lifecycle, not completed live renewal acceptance;
see [validation](validation.md).

The management host is separate from challenge workloads. Inventory addresses
it by SSH IP. The `hnh` zone publishes `ns1.microlab.hnh` and `ca`, `dns`, and
`git` A records; it publishes no AAAA record unless IPv6 is explicitly designed
and enabled. Those DNS records are owned by the DNS role, not this one.

## Provisioners and lifetimes

| Consumer | Provisioner | Lifetime | Renewal path |
| --- | --- | --- | --- |
| Caddy | `acme` (ACME) | max/default `168h` | Caddy's ACME client, directory at `https://127.0.0.1:4443/acme/acme/directory` |
| Technitium DoT/DoH | `microlab-technitium` (JWK, restricted names) | max/default `168h` | local `step ca renew --mtls=false` helper |

Both provisioners set `allowRenewalAfterExpiry: false`. The CA-wide claims and
each provisioner carry matching min/max/default values; the role refuses to
deploy if the seven-day lifetime is missing or if expired renewal is enabled.

### Why Technitium uses a restricted JWK enrollment

Self-hosted step-ca supports issuance policy only at the authority level; it
does not support per-provisioner policy. A per-provisioner "Technitium only"
name allowlist is therefore not natively enforceable in open-source step-ca.
MicroLab enforces the restriction in two layers:

1. `ca.json` applies an authority-wide DNS/IP policy limited to the MicroLab
   zone and loopback IP.
2. The only supported Technitium enrollment path is
   `/usr/local/sbin/step-ca-technitium-token`, which checks a root-owned
   allowlist and mints a single-use token carrying exactly the requested SAN.
   It will not mint arbitrary names.

The Technitium certificate is issued by the CA directly, not through Caddy.
That is deliberate: DoT is terminated by Technitium using its own enrolled
certificate and key.

## Local renewal architecture

The `technitium_tls` role installs:

- `/usr/local/sbin/technitium-tls-renew` — Python 3 helper using only the
  standard library plus `openssl` and `step`;
- `/etc/technitium-tls/` — root-only configuration directory (mode `0700`);
- `/etc/technitium-tls/renewal.env` — root-only environment (mode `0600`) with
  the CA URL/root, certificate name, Technitium config directory, API token,
  PFX path/password file, timing, and retry settings;
- `technitium-tls-renew.service` — one-shot root service with hardening and
  `SuccessExitStatus=75` for the lock-busy case;
- `technitium-tls-renew.timer` — every 15 minutes with jitter, persistent.

The manager is not a daemon and does not depend on Caddy, the Ansible
controller, or a public CA URL. The CA is reached at its loopback backend,
`https://127.0.0.1:4443`, using the pinned public root.

### Serialized execution

The helper takes an exclusive `flock` on
`/var/lib/technitium-tls/renew.lock`. A second invocation exits `75` and the
unit treats that as a successful skip. This prevents overlapping renewals and
PFX publication if the timer fires while an operator or deploy runs the helper.

The service uses `StateDirectory=technitium-tls` (mode `0750`) rather than a
`RuntimeDirectory`. A systemd `RuntimeDirectory` is removed when this oneshot
unit stops, which would let the timer acquire a new lock inode while a manual
helper still owned the old one. The durable state directory keeps one lock
inode and the status file across runs and reboots.

### Renewal timing

- Default early-renewal threshold: `72h` remaining.
- Default expiration alert: `24h` remaining.
- The helper checks the parsed `notAfter` itself. It only invokes
  `step ca renew --mtls=false --force` when inside the renewal window.
- `--mtls=false` uses the X5C token flow, which is appropriate for a direct
  loopback CA and avoids depending on mTLS client-auth behavior.
- Expired certificates are never renewed. The helper exits `3`, the timer is
  disabled by the role, and protected re-enrollment is required. Enabling
  `allowRenewalAfterExpiry` is explicitly out of design.

### Validation

Before publishing, the helper checks:

- certificate and private key exist and match;
- the chain verifies against the pinned root with `-purpose sslserver`;
- the leaf is currently valid;
- the SAN set is exactly the configured Technitium DNS name (no unexpected DNS
  or IP SANs);
- the EKU set is exactly `serverAuth`. Smallstep's default leaf template also
  adds `clientAuth`, so the JWK provisioner carries an explicit server-only
  `x509` template and the helper rejects a leaf with `clientAuth` or any other
  unwanted EKU;
- no IPv6 SAN is present unless IPv6 is explicitly enabled.

An invalid certificate is a hard failure; the helper does not repair it by
issuing a new one.

### Atomic PKCS#12 publication

Technitium consumes a PKCS#12 (`.pfx`) containing the private key and chain. The
helper:

1. creates a temporary PFX in the destination directory;
2. includes the intermediate chain when configured;
3. validates the PKCS#12, extracts the certificate, compares its SHA-256
   fingerprint to the PEM, and checks that a private key is present;
4. applies the configured restrictive owner/group/mode to the temporary file;
5. atomically `os.replace()`s it over the served path and fsyncs the directory.

Readers never see a partial PFX or a PFX that has not been validated.

### Publication retry

Renewal success is not publication success. On every run the helper compares the
served PFX certificate fingerprint with the current PEM. If they differ, it
publishes a fresh PFX and reconciles the TLS settings. If they already match it
does not rewrite the PFX; the live check then waits for Technitium to pick up
the file.

Technitium only reloads inside `SetDnsTlsCertificate` when the path or password
string differs. An unchanged POST is not a reload request. For files inside
Technitium's config folder the normalised relative path stays unchanged, and
for files outside it the absolute path stays unchanged, so a new PFX is picked
up by Technitium's 60-second mtime watcher. The live check therefore uses the
full `verify_retries`/`verify_delay` budget inside each publication attempt:
the default is 15 attempts at 5 seconds, or 70 seconds, which covers a full
watcher interval. Only after that budget is exhausted does the helper retry the
publication cycle (3 attempts by default). Failure exits `4` and reports the
last error and attempt count in the journal.

This also covers the case where renewal succeeded but Technitium did not reload
the PFX, or where the PFX was served with a stale certificate.

### Live verification

The helper connects to native DoT on `127.0.0.1:853` with `openssl s_client`,
using `-verify_hostname`, `-verify_return_error`, and the pinned root. It
requires a zero verification result, parses the served leaf, requires the exact
Technitium SAN set and server-only EKU, and compares the live SHA-256
fingerprint to the published certificate. The Ansible role also waits for both
local ports and repeats the live check after API reconciliation.

### Expiration alerts and status

If the certificate remains inside `alert_before` after the cycle, the helper
writes `/var/lib/technitium-tls/status.json` and exits `5`, causing systemd to
mark the unit failed so monitoring can alert. Successful runs write the serial,
fingerprint, renewal flag, publication attempts, retry count, remaining seconds,
and `notAfter`.

## Protected re-enrollment recovery

When the certificate is missing, expired, has the wrong names, or the key pair
is incomplete:

1. On the CA host, mint a new short-lived, single-use token:
   `/usr/local/sbin/step-ca-technitium-token dns.microlab.hnh`.
2. Pass it through encrypted inventory as
   `microlab_technitium_enrollment_token`.
3. Remove only the old certificate and key pair (not the PFX password file or
   API token) and rerun the role. The role generates a local P-256 key and a
   CSR, signs the CSR directly with the one-time token through
   `step ca sign`, and publishes the key pair. It will not create material
   without a token.
4. If the PFX password must change, update the vaulted value and let the helper
   publish a new PFX and reload Technitium.
5. Re-run the role; it validates the new certificate, publishes the PFX,
   reconciles settings, verifies the live certificate fingerprint, and only then enables the
   timer.

Do not enable renewal after expiry to avoid this procedure. Expired renewal
would let a stolen key extend its own trust.

## Technitium API reconciliation

The role reads `/api/settings/get` and only posts if a desired value differs.
The reconciled settings are:

- `enableDnsOverHttp: true`, `dnsOverHttpPort: 8053`;
- `dnsOverHttpRealIpHeader: X-Real-IP`;
- `dnsReverseProxyNetworkACL: 127.0.0.1/32` (only the local reverse proxy);
- `enableDnsOverHttps: false` (TLS is terminated by the local proxy);
- `enableDnsOverTls: true`, `dnsOverTlsPort: 853`;
- `dnsTlsCertificatePath` = the published PFX, normalised the way Technitium
  stores it. A path inside Technitium's config folder (`/etc/dns`) is compared
  and posted as `tls/dns.pfx`; a path outside stays absolute;
- `dnsTlsCertificatePassword` = the protected PFX password.

Technitium stores in-config-folder paths relative and returns that relative form
from `/api/settings/get`. The role normalises both the desired and read-back
values against `microlab_technitium_config_dir`, so a correct PFX no longer
shows perpetual drift and does not fail the read-back assertion.

The API token is passed as `Authorization: Bearer`. Secret-bearing tasks use
`no_log` and `diff: false`.

## Operational checks

```sh
systemctl status technitium-tls-renew.timer
systemctl status technitium-tls-renew.service
journalctl -u technitium-tls-renew.service --since -24h
cat /var/lib/technitium-tls/status.json

# Manual, serialized run (uses the same lock).
/usr/local/sbin/technitium-tls-renew --config /etc/technitium-tls/renewal.env

# Validate only; does not renew or publish.
/usr/local/sbin/technitium-tls-renew --config /etc/technitium-tls/renewal.env --check-only

# Verify the live 853 certificate fingerprint only.
/usr/local/sbin/technitium-tls-renew --config /etc/technitium-tls/renewal.env --verify-only
```

Exit codes: `0` success, `1` validation/renewal failure, `2` configuration,
`3` protected re-enrollment required, `4` publication/live verification failed,
`5` expiration alert, `75` another invocation holds the lock.

## Integration variables

Other roles must not write DoT certificate settings directly. The published
interface is:

| Role | Variable / output | Meaning |
| --- | --- | --- |
| `step_ca` | `microlab_step_ca_ca_url` | Direct loopback CA API. |
| `step_ca` | `microlab_step_ca_certs_dir` | Public root and intermediate directory. |
| `step_ca` | `microlab_step_ca_trust_store_path` | Managed public trust bundle path. |
| `step_ca` | `acme` / `microlab-technitium` | Provisioner names. |
| `technitium_tls` | `microlab_technitium_pfx_path` | PFX consumed by native DoT. |
| `technitium_tls` | `microlab_technitium_pfx_password` | PFX password (vault). |
| `technitium_tls` | `microlab_technitium_api_token` | Technitium API bearer token (vault). |
| `technitium_tls` | `microlab_technitium_timer_unit` | Independent renewal timer. |

All canonical role inputs use the `microlab_` prefix. The PFX path defaults to
`/etc/dns/tls/dns.pfx`, the key to `/etc/dns/tls/dns.key`, and the password to
the vaulted `microlab_technitium_pfx_password`. For compatibility with the
repository's existing shared interface, the role also consumes the
`micolab_technitium_tls_cert_path`, `micolab_technitium_tls_key_path`,
`micolab_technitium_tls_cert_password`, `micolab_technitium_api_token`,
`micolab_technitium_enrollment_token`, and `micolab_technitium_dot_port`
aliases when they are defined.

## Limitations

- Self-hosted step-ca has no per-provisioner issuance policy. The Technitium
  name restriction is enforced by the token helper and the authority policy, as
  described above.
- Technitium exposes no bind-address control for DoH/DoT. Its application
  ACL restricts DoH to the loopback proxy; baseline provides the host firewall.
  Verify additionally requires a loopback-only 8053 socket. Application ACLs
  alone do not satisfy that check; test the pinned release during deployment.
  Native DoT `853` must be constrained by the host firewall.
- DoH on `8053` is local plain HTTP behind a TLS terminator. It must never be
  exposed directly.
- No AAAA record, IPv6 SAN, or IPv6 ACL is published unless IPv6 support is
  explicitly designed and enabled. The `ns1`, `ca`, `dns`, and `git` A records
  and the `hnh` zone are owned by the DNS role, not this role.
- The tests are offline: `tests/test_technitium_tls_helper.py` covers
  certificate/EKU validation, locking, atomic publication, path normalisation,
  and retry budgets; `tests/test_role_logic.py` covers the CA state matrix,
  path idempotence, and safety-critical role wiring;
  `tests/test_step_ca_preflight.py` runs the real CA preflight and first-deploy
  material include through `ansible-playbook` against OpenSSL-generated
  throwaway material in temporary directories. That single-localhost test
  cannot detect controller/target confusion, so
  `tests/test_step_ca_cross_host.py` runs the same task files with the
  controller on `connection: local` and the target in a test-only bubblewrap
  mount namespace that masks or overlays the controller source directory. The
  cross-host test proves controller-only sources validate and deploy,
  same-named target files cannot substitute their bytes, target-only root
  escrow files are found, and target material validation stays on the target.
  Neither test executes the full `configure.yml` rendering or the
  service/health gates. No test contacts a live CA or Technitium instance.

## Upstream references checked

- step-ca configuration and `dnsNames`/IPv4 SAN behavior:
  <https://smallstep.com/docs/step-ca/configuration/>
- step-ca provisioner types, ACME directory shape, and seven-day claim fields:
  <https://smallstep.com/docs/step-ca/provisioners/>
- Self-hosted step-ca authority-only policy limitation:
  <https://smallstep.com/docs/step-ca/policies/>
- step-ca renewal and `step ca renew --mtls=false` X5C token flow:
  <https://smallstep.com/docs/step-ca/renewal/> and
  <https://smallstep.com/docs/step-cli/reference/ca/renew/>
- Technitium settings API (`enableDnsOverHttp`, `dnsOverHttpPort`,
  `dnsOverHttpRealIpHeader`, `dnsReverseProxyNetworkACL`,
  `enableDnsOverTls`, `dnsOverTlsPort`, `dnsTlsCertificatePath`,
  `dnsTlsCertificatePassword`):
  <https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md>
