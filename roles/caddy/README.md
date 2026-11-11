# Role: `caddy`

Experimental implementation; live deployment acceptance remains unexercised.
See [validation evidence and limits](../../docs/validation.md).

Pinned stock Caddy TLS frontend for the MicroLab management host. Caddy is the
HTTPS frontend; every upstream connection uses loopback on the same host.
Technitium terminates native DoT separately.

## What it enforces

- Stock Caddy binary installed from an offline, SHA-256-pinned artifact.
- Native systemd unit; persistent state under `/var/lib/caddy`.
- Admin API bound to `127.0.0.1:2019` only.
- Explicit step-ca ACME issuer, trusted against the public step-ca root PEM,
  HTTP-01 only, TLS-ALPN challenge disabled. The only accepted provisioner is
  `acme` and the only accepted directory is exactly
  `https://127.0.0.1:4443/acme/acme/directory`. Before rendering, the role
  reads `/provisioners` and fails unless the live CA publishes `acme`. It never
  adopts an alternative provisioner or builds a different endpoint.
- Never disables upstream TLS verification: the CA frontend and ACME client
  both verify the step-ca certificate chain and its `127.0.0.1` IP SAN.
- Caddyfile validated before reload; the unit also validates before start.
- Real-certificate health gates for every enabled site (chain verified against
  the step-ca root, hostname checked, expiry checked, Caddy's internal issuer
  rejected).
- CA frontend restricted to `micolab_caddy_management_cidrs`.
- Exact `/dns-query` reverse proxy to `127.0.0.1:8053`, preserving the URI
  query, restricted to `micolab_caddy_dns_client_cidrs`.
- Every other path on the DNS hostname is the Technitium admin console,
  proxied to `127.0.0.1:5380` and restricted to `micolab_caddy_admin_cidrs`.
  DNS client CIDRs alone never grant admin access.
- Git admin UI/API routes restricted to `micolab_caddy_admin_cidrs`; the git
  site is rendered only when `micolab_caddy_enable_git` is true and Forgejo's
  health endpoint has passed.
- `X-Real-IP` and `X-Forwarded-For` are overwritten with `{remote_host}` on
  every proxied route. Caddy is the edge and configures no `trusted_proxies`,
  so client-supplied forwarding headers cannot spoof the source address.
- Technitium only reads `X-Real-IP` from addresses listed in its
  `webServiceReverseProxyAddresses` setting. The DNS role sets exactly
  `127.0.0.1` and `webServiceRealIpHeader=X-Real-IP` and verifies the readback,
  so Technitium records the real client instead of the loopback proxy. This
  Caddy role does not configure that DNS setting; if an older DNS role leaves it
  unset, only source logging degrades. Caddy still overwrites the header, so
  the admin console cannot be reached with a spoofed client address.
- Loopback is appended to each remote matcher for local health gates only. It
  does not add any remote access.

## Required variables

| Variable | Required | Description |
| --- | --- | --- |
| `micolab_caddy_version` | yes | Exact stock Caddy release, without a leading `v`, e.g. a version recorded in the dependency bundle. |
| `micolab_caddy_checksums` | yes | Map with `amd64` and/or `arm64` keys to 64-hex SHA-256 digests of the official release tarballs. |
| `micolab_caddy_artifact_src_amd64` | one arch | Controller path to the pre-staged `caddy_<version>_linux_amd64.tar.gz`. |
| `micolab_caddy_artifact_src_arm64` | one arch | Controller path to the pre-staged `caddy_<version>_linux_arm64.tar.gz`. |
| `micolab_caddy_acme_trusted_roots` | yes | Target path to the **public** step-ca root certificate PEM (shared trust bundle). Must be readable by the `caddy` user. |
| `micolab_caddy_management_cidrs` | yes (CA) | Remote management networks allowed to reach `ca.microlab.hnh`. |
| `micolab_caddy_dns_client_cidrs` | yes (DNS) | Remote DNS clients allowed to reach `/dns-query`. |
| `micolab_caddy_admin_cidrs` | yes (DNS + git) | Remote networks allowed to reach the Technitium admin console on the DNS hostname and Forgejo admin UI/API routes. |

If `micolab_caddy_version` is empty and `micolab_staged_artifacts` contains a
matching `caddy` entry, the role adopts that version, SHA-256, and controller
path. If no staged entry exists and `micolab_caddy_allow_online_download` is
true, it fetches the official release URL and verifies the checksum. Offline
staging is the default.

## Optional variables

| Variable | Default | Description |
| --- | --- | --- |
| `micolab_caddy_staged_artifact_name` | `caddy` | Name in the shared `micolab_staged_artifacts` list, used only when explicit pins are empty. |
| `micolab_caddy_enable_ca` | `true` | Render the `ca.microlab.hnh` frontend. |
| `micolab_caddy_enable_dns` | `true` | Render the `dns.microlab.hnh` DoH + Technitium admin frontend. |
| `micolab_caddy_enable_git` | `false` | Render the `git.microlab.hnh` frontend after a Forgejo health gate. |
| `micolab_caddy_acme_provisioner` | `acme` | Must remain `acme`; any other value fails closed. No auto-adoption is performed. |
| `micolab_caddy_acme_directory` | `https://127.0.0.1:4443/acme/acme/directory` | Must be exactly this endpoint; any other value fails closed. |
| `micolab_caddy_ca_host` | `ca.microlab.hnh` | CA frontend hostname. |
| `micolab_caddy_dns_host` | `dns.microlab.hnh` | DoH hostname. |
| `micolab_caddy_git_host` | `git.microlab.hnh` | Forgejo hostname. |
| `micolab_caddy_http_port` | `80` | Caddy HTTP port. |
| `micolab_caddy_https_port` | `443` | Caddy HTTPS port. |
| `micolab_caddy_ca_upstream_host` | `127.0.0.1` | Must be loopback. |
| `micolab_caddy_ca_upstream_port` | `4443` | step-ca HTTPS port. |
| `micolab_caddy_dns_upstream_host` | `127.0.0.1` | Must be loopback. |
| `micolab_caddy_dns_upstream_port` | `8053` | DNS-over-HTTPS backend port. |
| `micolab_caddy_admin_upstream_host` | `127.0.0.1` | Technitium admin console upstream; must be loopback. |
| `micolab_caddy_admin_upstream_port` | `5380` | Technitium admin console port. |
| `micolab_caddy_verify_doh` | `true` | Run the real DoH probe. Set false for the first Caddy pass before `technitium_tls` creates 8053; a later phase must set it true. |
| `micolab_caddy_forgejo_upstream_host` | `127.0.0.1` | Must be loopback. |
| `micolab_caddy_forgejo_upstream_port` | `3000` | Forgejo HTTP port. The shared `micolab_caddy_forgejo_upstream` address is accepted as documentation of the same loopback contract. |
| `micolab_caddy_forgejo_health_url` | `http://127.0.0.1:3000/api/healthz` | Pre-render health gate for the git site. |
| `micolab_caddy_dns_probe_name` | `ns1.microlab.hnh` | Name used by the post-render DoH health gate. |
| `micolab_caddy_admin_host` | `127.0.0.1` | Caddy admin bind address; loopback only. |
| `micolab_caddy_admin_port` | `2019` | Caddy admin port. |
| `micolab_caddy_service_name` | `caddy` | systemd unit name. |
| `micolab_caddy_storage_dir` | `/var/lib/caddy/.local/share/caddy` | Persistent Caddy state. |
| `micolab_caddy_health_retries` | `30` | Retries for backend and certificate gates. |
| `micolab_caddy_health_delay` | `5` | Seconds between gate retries. |
| `micolab_caddy_certificate_retries` | `30` | Retries for real-certificate gates. |
| `micolab_caddy_certificate_delay` | `5` | Seconds between certificate retries. |
| `micolab_caddy_expected_issuer_contains` | `""` | Optional substring that must appear in the served certificate issuer. |

## Dependencies

Run this role with `become: true`; it creates system users, installs the binary, and manages systemd.

The target must already provide Debian 12/13, systemd, Python 3, `openssl`,
`curl`, `ss`, `tar`, and the step-ca public root certificate. The role does not
install OS packages and does not contact hosts from the controller.

## Ordering

The site playbook keeps this order: DNS, CA, first Caddy pass, encrypted DNS,
Forgejo, final Caddy pass, verify.

1. CA and DNS roles are deployed and their loopback listeners are healthy.
2. The first Caddy pass renders CA and DNS (DoH route + Technitium admin
   proxy) with `micolab_caddy_enable_git: false` and
   `micolab_caddy_verify_doh: false`. It proves the real certificates and the
   DNS admin route, but does not require the not-yet-created 8053 backend.
3. `technitium_tls` creates the DoH/DoT listeners.
4. The explicit Caddy/DoH readiness phase runs `tasks_from: health_doh` with
   `micolab_caddy_verify_doh: true`, which waits for 8053 and probes the exact
   `/dns-query` path.
5. Forgejo is deployed and healthy.
6. The final Caddy pass enables the Git vhost only after Forgejo's health gate
   passes.
7. `roles/verify` performs the end-to-end DNS/DoH/DoT/Git clone/push and
   external ACL checks.

DNS A records must already point at the management host's inventory SSH IP
before Caddy can complete HTTP-01 issuance.
