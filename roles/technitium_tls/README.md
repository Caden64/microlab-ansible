# technitium_tls

Experimental implementation; live deployment acceptance remains unexercised.
See [validation evidence and limits](../../docs/validation.md).

Manages Technitium DNS TLS on the shared management host:

- reconciles DNS-over-HTTP on local port `8053` through the Technitium API,
  behind the local TLS terminator, with `dnsOverHttpRealIpHeader=X-Real-IP`
  and `dnsReverseProxyNetworkACL` restricted to `127.0.0.1/32`;
- enrolls Technitium's own certificate directly from the restricted step-ca
  provisioner, never through Caddy;
- publishes native DoT on `853` from a validated, atomically replaced PKCS#12;
- installs an independent local systemd timer/helper that renews early, verifies
  names/chain/server-only EKU, retries publication when the PEM and served PFX
  differ, and verifies the live 853 certificate fingerprint.

The role does not install Technitium, does not create a service account, and
does not restart the DNS application. It fails closed if the existing service
account, CA trust material, or protected secrets are absent.

## Required inventory/vault inputs

| Variable | Required | Meaning |
| --- | --- | --- |
| `microlab_technitium_pfx_password` | yes, vault | PFX password. |
| `microlab_technitium_api_token` | yes, vault | Technitium API bearer token with Settings: Modify. |
| `microlab_technitium_enrollment_token` | first enrollment / re-enrollment only | Single-use token from `/usr/local/sbin/step-ca-technitium-token` on the CA host. |
| `microlab_technitium_service_user` | default exists | Existing Technitium user, default `dns-server`. |
| `microlab_technitium_service_group` | default exists | Existing Technitium group, default `dns-server`. |
| `microlab_technitium_ca_root_cert` | yes, file | Public root, default `/etc/step-ca/certs/root_ca.crt`. |
| `microlab_technitium_ca_chain_cert` | yes, file | Intermediate chain, default `/etc/step-ca/certs/intermediate_ca.crt`. |

## Variable interface

| Variable | Default |
| --- | --- |
| `microlab_technitium_ca_url` | `https://127.0.0.1:4443` |
| `microlab_technitium_cert_name` | `dns.microlab.hnh` |
| `microlab_technitium_config_dir` | `/etc/dns` (Technitium config folder used to normalise `dnsTlsCertificatePath`) |
| `microlab_technitium_cert_dir` | `/etc/dns/tls` |
| `microlab_technitium_cert_path` | `<cert_dir>/dns.crt` |
| `microlab_technitium_key_path` | `<cert_dir>/dns.key` |
| `microlab_technitium_pfx_path` | `<cert_dir>/dns.pfx` |
| `microlab_technitium_pfx_password_file` | `<cert_dir>/pfx.pass` |
| `microlab_technitium_pfx_owner` / `_group` / `_mode` | `root` / service group / `0640` |
| `microlab_technitium_api_url` | `http://127.0.0.1:5380` |
| `microlab_technitium_doh_port` | `8053` |
| `microlab_technitium_dot_port` | `853` |
| `microlab_technitium_doh_real_ip_header` | `X-Real-IP` |
| `microlab_technitium_doh_reverse_proxy_acl` | `[127.0.0.1/32]` |
| `microlab_technitium_renew_before` | `72h` |
| `microlab_technitium_alert_before` | `24h` |
| `microlab_technitium_publication_retries` | `3` |
| `microlab_technitium_verify_retries` / `_delay` | `15` / `5` seconds (70-second budget covers Technitium's 60-second watcher) |
| `microlab_technitium_helper_path` | `/usr/local/sbin/technitium-tls-renew` |
| `microlab_technitium_renewal_env_file` | `/etc/technitium-tls/renewal.env` (parent dir `0700`) |
| `microlab_technitium_lock_file` | `/var/lib/technitium-tls/renew.lock` |
| `microlab_technitium_status_file` | `/var/lib/technitium-tls/status.json` |
| `microlab_technitium_timer_unit` | `technitium-tls-renew.timer` |
| `microlab_technitium_service_name` | `dns` |
| `microlab_technitium_ipv6_enabled` | `false` |

Compatibility aliases from the repository's existing shared interface are
consumed when present: `micolab_technitium_tls_cert_path`,
`micolab_technitium_tls_key_path`, `micolab_technitium_tls_cert_password`,
`micolab_technitium_api_token`, `micolab_technitium_enrollment_token`, and
`micolab_technitium_dot_port`. The public Caddy DoH port alias
`micolab_technitium_doh_port` is deliberately not used for the local Technitium
backend, which must stay on 8053.

## Enrollment and renewal lifecycle

Before this phase on a fresh host, create the Technitium Settings: Modify API
token through its loopback API and store it in protected inventory. The DNS
role rotates the admin password but does not provision this token. See
[first bootstrap](../../README.md#deployment-order-and-first-bootstrap).

1. On the CA host, mint a short-lived, single-use token restricted to the
   allowlisted Technitium name:
   `/usr/local/sbin/step-ca-technitium-token dns.microlab.hnh`.
2. Pass it as `microlab_technitium_enrollment_token` from encrypted inventory.
   The role generates a local P-256 key and CSR, asks step-ca directly to sign
   it for `168h`, and publishes the pair. It never creates a key or certificate
   when no token is present.
3. The helper validates the certificate and publishes a PFX. The PFX is built in
   a temporary file, validated, chowned/moded, and atomically renamed.
4. The Technitium API reloads native DoT from the PFX and the role verifies the
   live 853 certificate fingerprint, SANs, server-only EKU, and chain.
5. The role enables `technitium-tls-renew.timer` only after all gates pass.

The timer runs every 15 minutes with jitter. The helper locks with `flock` on a
durable `/var/lib/technitium-tls/renew.lock`; a second invocation exits `75`,
which the unit treats as a successful skip. The service uses
`StateDirectory=technitium-tls`, not a `RuntimeDirectory`, so stopping the
oneshot unit cannot delete the lock inode or status file while a manual helper
still owns the old lock.

## Helper behavior

- Renewal uses `step ca renew --mtls=false --force` (X5C token flow) and only
  when the certificate is inside the `renew_before` window.
- An expired certificate is never renewed. The helper exits `3`, the role
  disables the timer, and protected re-enrollment is required.
- The helper requires exactly the `serverAuth` EKU. The role's JWK provisioner
  uses an explicit server-only x509 template, and the helper rejects a leaf with
  `clientAuth` or any other extra EKU.
- After renewal, and on every run, the helper compares the PEM fingerprint with
  the certificate inside the served PFX. A mismatch triggers a fresh PFX; a
  match is not rewritten.
- Technitium stores in-config-folder PFX paths relative (`tls/dns.pfx`). The
  helper and role normalise the desired and read-back paths so the settings API
  is idempotent. Because an unchanged path/password POST is not a reload
  request, live verification uses the full 70-second retry budget to cover the
  60-second file watcher before republishing.
- Publication/live-fingerprint verification is retried `publication_retries`
  times. Failures are logged with attempt counts and the helper exits `4`.
- If the certificate is inside `alert_before`, the helper writes a status file
  and exits `5` so systemd surfaces the expiration alert.

## Limitations

- Technitium has no separate bind-address setting for DoH/DoT. DoH access is
  restricted at the application layer to loopback via
  `dnsReverseProxyNetworkACL`; native DoT `853` still listens on the host's
  interfaces and must be constrained by the host firewall, which is outside
  this role (`baseline` manages the site firewall). Verify separately requires
  8053 to bind only loopback; application ACLs alone do not meet that check.
  This remains a pinned-release deployment compatibility gate.
- DoH on local `8053` is plain HTTP behind the local TLS terminator. Do not
  expose `8053` directly.
- No IPv6 SAN, AAAA record, or IPv6 ACL is emitted unless
  `microlab_technitium_ipv6_enabled` is explicitly enabled.
- The helper corrects TLS publication, not DNS records. The `hnh` zone,
  `ns1`/`ca`/`dns`/`git` A records, and any AAAA policy are managed by
  `technitium_dns`.
- Tests live in `tests/test_technitium_tls_helper.py` and
  `tests/test_role_logic.py`. They cover validation, server-only vs mixed EKU,
  locking, atomic publication, expired-certificate refusal, path normalisation,
  the CA state matrix, and publication/retry behavior.
