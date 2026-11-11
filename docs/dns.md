# MicroLab DNS and management-plane deployment

Baseline validates the host and manages its nftables ingress policy;
`technitium_install` installs pinned Technitium/runtime archives;
`technitium_dns` configures the authoritative zone, recursion, records, and
host resolver. These roles are integrated by `playbooks/site.yml`.

This implementation is experimental. The example inventory contains required
placeholders, and live DNS/firewall/deployment acceptance has not been
exercised. See [validation evidence and limits](validation.md) and
[first bootstrap](../README.md#deployment-order-and-first-bootstrap).

## Topology and invariants

```
                         management host (Debian arm64/amd64)
  lab/VPN clients ---> nftables ACL
                          |-- Caddy :80/:443 -------> step-ca :4443
                          |                           Forgejo :3000
                          |                           Technitium admin :5380 (loopback)
                          |                           Technitium DoH :8053 (local proxy + ACL)
                          |-- Technitium DNS :53/udp+tcp
                          |-- Technitium DoT :853/tcp (technitium_tls)
                          '-- Technitium DoQ :853/udp (only if configured)
```

- The management host is a dedicated host. It must be in
  `microlab_management` and must not be in `microlab_challenge`.
  `playbooks/site.yml` targets only `microlab_management`; baseline asserts the
  separation before any package or service change.
- All loopback services share the management host. `ca`, `dns`, and `git` are
  A records on that host.
- `hnh` is an authoritative Primary zone. Its NS target is `ns1.microlab.hnh`
  and the in-zone A record for `ns1` is the glue address.
- AAAA records are never inferred. IPv6 is disabled unless
  `micolab_dns_ipv6_enabled: true` and all four IPv6 addresses are supplied.
- SSH is retained from the administrative CIDRs only. The inventory
  `ansible_host` must be an IP literal, not a DNS name.

## Ordered phases

`playbooks/site.yml` executes, serialized per host:

1. `baseline` - fail-closed inventory/fact/pin/storage/time/package/port checks,
   then the `micolab-firewall` nftables ingress policy.
2. `technitium_install` - verify offline artifacts, install the pinned ASP.NET
   Core runtime and Technitium release, install the hardened native systemd
   unit, start Technitium, wait for the loopback API.
3. `technitium_dns` - start and validate the controlled local recursion
   fixture, rotate the bootstrap password, reconcile settings, create the
   `hnh` zone plus the fixture conditional-forwarder zone, converge owned
   records, restart once on change, run local authoritative UDP/TCP/SOA/AAAA
   (AA-flagged) and fixture-recursion gates, run remote probe classes, then
   switch the resolver.
4. `step_ca` - internal CA and management-host public trust installation.
5. `caddy` - first pass with **both the CA and DNS vhosts rendered**. The DNS
   admin proxy and certificate are proven here; the `/dns-query` DoH probe is
   deferred because the 8053 backend is created in phase 6.
6. `technitium_tls` - DoH/DoT using CA material.
   Phase 6b. runs Caddy's deferred `tasks_from: health_doh` readiness probe
   before Forgejo.
7. `forgejo` - loopback Git service.
8. `caddy` - second pass with `micolab_caddy_enable_git: true`; the DNS vhost
   remains rendered and DoH has passed its readiness gate.
9. `verify` - end-to-end checks, including disposable-repository writes.

Handlers are flushed between phases. The playbook does not start any challenge
workload or modify external infrastructure.

## Required inventory inputs

`ansible.cfg` points at `inventories/example`. `playbooks/group_vars` is a
symlink to the repository's `group_vars/` so the shared `micolab_` defaults are
loaded when the playbook is invoked as `playbooks/site.yml`. Inventory group
vars are more specific and override those defaults.

Copy `inventories/example` and replace every `REPLACE_` value. The important
required inputs for these roles are:

| Variable | Meaning |
|---|---|
| `ansible_host` | IPv4 SSH address of the management host (no hostname) |
| `micolab_expected_os` / `micolab_expected_architecture` | `Debian`; `arm64` or `amd64` |
| `micolab_admin_cidrs` | Admin IPv4 networks for SSH and admin web |
| `micolab_client_cidrs` | Lab/VPN IPv4 networks for DNS and HTTPS |
| `micolab_admin_cidrs_v6`, `micolab_client_cidrs_v6` | Optional IPv6 ACLs |
| `micolab_dns_authoritative_only_cidrs` | Firewall-admitted, recursion-denied IPv4 networks |
| `micolab_dns_authoritative_only_cidrs_v6` | Same, IPv6 (only when IPv6 is enabled) |
| `micolab_dns_fixture_upstream` | Required reachable local `IPv4:port` upstream for the cold offline recursion fixture |
| `micolab_dns_fixture_zone` | Required distinct fixture zone (not `hnh`, not under `micolab_domain`) |
| `micolab_dns_fixture_name` | Required name inside the fixture zone |
| `micolab_dns_fixture_expected_ip` | Required known A answer from the local fixture |
| `micolab_dns_addresses` | IPv4 for keys `ns1`, `ca`, `dns`, `git` |
| `micolab_dns_ipv6_addresses` | IPv6 for the same keys only when enabled |
| `micolab_staged_artifacts` | Offline artifact name/version/path/SHA256 list |
| `micolab_technitium_version` | Exact Technitium release version |
| `micolab_technitium_admin_password` | Vaulted admin password, not `admin` |
| `micolab_trust_targets` | FQDN/role list for CA trust consumers |
| `micolab_max_powered_off_interval_seconds` | Positive lifecycle bound |
| `micolab_verify_git_repo` | Real Forgejo repository for verification |

The vault file is not loaded from the example. See
`inventories/vault.yml.example` for the two supported patterns. The
role never writes the administrator password to disk or logs it.

Other roles require their own staged artifacts and secrets (step-ca, Caddy,
Forgejo). Their `defaults/main.yml` and READMEs are the source of truth. In
particular, `technitium_tls` requires:

- `micolab_technitium_api_token` - a bearer API token created through the
  loopback API (`POST /api/user/createToken` with `tokenName`, while holding a
  valid admin session) and stored in the vault.
- `micolab_technitium_enrollment_token` - a single-use enrollment token for
  first issuance or protected re-enrollment.
- `micolab_technitium_tls_cert_password` (mapped to the PFX password).

These are deliberately empty in `group_vars/all.yml`; the TLS phase fails
closed until the operator supplies them.

## Pinned, offline artifacts

`technitium_install` never downloads. Each artifact is a controller-local file
with an exact version and SHA256 in `micolab_staged_artifacts`:

- `technitium`: the official portable `DnsServerPortable.tar.gz` release.
- `dotnet-aspnetcore-runtime`: the official ASP.NET Core runtime archive for
  the host architecture.

Baseline checks the artifact on the controller before installation (after
creating its validation directories/helper), the
install role checks it again after transfer, and both roles compare the running
Technitium version to the pin. The upstream portable archive is framework
dependent: its `DnsServerApp.runtimeconfig.json` targets
`Microsoft.NETCore.App 10.0.0` and `Microsoft.AspNetCore.App 10.0.0`, so the
ASP.NET Core runtime is mandatory. The role runs Technitium's `--icu-test`
before starting the service.

Do not copy a checksum from this document. Obtain the archive from the official
Technitium release source, compute SHA256 yourself, stage it, and put that value
in inventory. Match the runtime to the pinned Technitium release; deployment
pins must be operator-verified.

Upstream references:

- <https://technitium.com/dns/>
- <https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md>
- <https://github.com/TechnitiumSoftware/DnsServer/blob/master/DnsServerApp/install.sh>

## Technitium layout and systemd

- Install tree: `micolab_technitium_install_dir` (`/opt/technitium/dns`)
- Persistent data/config: `micolab_technitium_config_dir` (`/etc/dns`)
- Logs: `micolab_technitium_log_dir` (`/var/log/technitium/dns`)
- Runtime: `micolab_dotnet_install_dir` (`/opt/dotnet`), symlinked at
  `/usr/local/bin/dotnet`
- Service: `dns.service`, user/group `dns-server`, `Restart=on-failure`,
  `ProtectSystem=strict`, `CAP_NET_BIND_SERVICE`, read-only install tree.

The unit sets `DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1` and
`DNS_SERVER_WEB_SERVICE_HTTP_PORT=5380`. Upstream reads those environment
variables only when `webservice.config` does not exist. That closes the
first-start window; the DNS role then persists the same loopback binding
through `/api/settings/set`. The nftables policy also has no external 5380
rule. This is defense in depth, not a substitute for the API setting.

Logs are bounded twice: Technitium settings `maxLogFileDays` /
`maxStatFileDays`, and a `logrotate` file with `maxsize 100M`, `maxage`, and
`copytruncate`. Kernel drop logging is rate-limited to 5/minute.

## API behavior used

All API calls are loopback-only (`http://127.0.0.1:5380`) and use POST form
data. Authentication uses the bearer session token returned by login.

1. `POST /api/user/login` with `user`, `pass`, `includeInfo`.
   The role first tries the vaulted password. If that fails, it tries the
   upstream bootstrap password once, rotates it with
   `POST /api/user/changePassword` (`pass`, `newPass`), and re-authenticates.
   If neither credential works, the role fails without guessing or printing a
   password.
2. `GET /api/status` - requires `hasDefaultCredentials=false` before proceeding.
3. `GET /api/settings/get`, then `POST /api/settings/set`. The API overwrites
   only supplied fields. The role sends only fields whose normalized current
   value differs. List settings (`recursionNetworkACL`,
   `zoneTransferAllowedNetworks`) are canonicalized exactly as
   `TechnitiumLibrary.Net.NetworkAddress` prints them: IPv4 `/32` and IPv6
   `/128` are written as bare addresses, IPv6 is compressed, host bits are
   masked, and a leading `!` deny marker is preserved. Current entries are
   merged with the required entries in order without sorting; the role fails
   closed if a first-match entry shadows a managed entry with opposite
   polarity. The ACL is rejected if it contains a default route or denies
   loopback. Every `micolab_dns_authoritative_only_cidrs` (and `_v6`) network
   must be *effectively denied* by first-match semantics, both in the merged
   payload and in the readback. A pre-existing broad allow such as
   `10.0.0.0/8` that covers an authoritative-only `10.99.0.0/24` is reported
   with the exact blocking entry and the run fails; the role never deletes or
   reorders an unknown current ACL entry to hide the conflict. An explicit
   covering `!deny` placed before the broad allow is accepted.
4. `GET /api/zones/list`, then `POST /api/zones/create` with `type=Primary` only
   when the exact zone is absent.
5. `GET /api/zones/records/get?listZone=true`, then `records/add`,
   `records/update`, or `records/delete`. Records created by this role carry
   `comments=micolab-managed`. Only those records are updated or deleted.
   Unknown records, and records whose comments were changed by a human, are
   preserved. Exact unowned records are not claimed or duplicated.
   The fixture Conditional Forwarder is separate: the complete FWD set is
   read before any record mutation, and the zone is owned only when its sole
   apex FWD record carries the exact comment line
   `micolab-managed:fixture-forwarder`. An unmarked FWD, several owned FWD
   records, a non-UDP or DNSSEC-validating owned FWD, or an owned FWD at a
   non-apex name is a conflict: the run fails with zero zone, FWD, or query
   ACL mutation. Unknown non-FWD records in the zone are preserved. When the
   configured fixture endpoint changes, only the owned FWD's `forwarder` is
   updated; its protocol, priority, proxy fields, TTL, and complete comment
   (including any human note beside the marker) are echoed back unchanged.
6. `POST /api/user/logout` at the end of the role.

The settings role deliberately does **not** write
`enableDnsOverTls`, `enableDnsOverHttps`, or `enableDnsOverQuic`. Those are
owned by `technitium_tls`; re-running `technitium_dns` therefore cannot switch
off encrypted protocols enabled later.

DNS role settings include:

- `dnsServerDomain=ns1.microlab.hnh`
- `dnsServerLocalEndPoints=0.0.0.0:53` (IPv4 only) or
  `0.0.0.0:53,[::]:53` when IPv6 is enabled
- `recursion=UseSpecifiedNetworkACL`, ACL = admin + client + extra allowed
  networks (merged). `micolab_dns_authoritative_only_cidrs` is deliberately
  excluded from this ACL; it is firewall-admitted only.
- `zoneTransferAllowedNetworks` = admin networks (merged)
- `webServiceLocalAddresses=127.0.0.1`, `webServiceHttpPort=5380`
- `webServiceReverseProxyAddresses=127.0.0.1` exactly, and
  `webServiceRealIpHeader=X-Real-IP`. Caddy is the only admin reverse proxy;
  it connects over IPv4 loopback and overwrites `X-Real-IP`. Arbitrary proxy
  networks are replaced, never merged, and `::1` is not trusted unless the
  actual Caddy upstream uses it. The role asserts the trusted address equals
  `micolab_caddy_admin_upstream_host` and reads both fields back after the
  mutation and after the persistence restart. The field names and ACL order
  follow the upstream APIDOCS (`webServiceReverseProxyAddresses` is a
  first-match ACL, default deny).
- `loggingType=File`, `logFolder=/var/log/technitium/dns`,
  `maxLogFileDays`, `maxStatFileDays`, `logQueries`
- update checks and DNS app auto-update disabled for an offline deployment
- `ipv6Mode=Disabled` unless IPv6 is explicitly enabled

DoH is the loopback upstream `127.0.0.1:8053`; Caddy terminates public HTTPS on
443. DoT is 853/tcp. DoQ is not enabled by the current TLS role; the firewall
opens 853/udp only when `micolab_dns_enable_doq=true`, and that requires a
matching TLS implementation.

`micolab_dns_enable_dot` and `micolab_dns_enable_doh` currently also drive the
firewall ports. The `technitium_tls` role in this repository enables DoH/DoT
unconditionally, so leave both flags true while that phase is present; setting
them false would block the ports the TLS phase just enabled.

## Records and ownership

The role manages:

- apex `hnh NS ns1.microlab.hnh`
- A (and optional AAAA) for `ns1`, `ca`, `dns`, `git` under `microlab.hnh`
- optional extra A/AAAA records from `micolab_dns_extra_records`

IPv4/IPv6 values are canonicalized by the role's small `micolab_ip` filter so
an expanded IPv6 inventory value and Technitium's compressed answer are
treated as the same record across runs.

Reconciliation is planned against the **complete desired identity set**, not
one record at a time. This matters for a multi-valued RRset: when both
`1.2.3.4` and `1.2.3.5` are desired for the same A name, neither value is ever
treated as stale while the other is being processed. The plan is
`(name, type, canonical value)` based:

- an exact record (owned or unowned) satisfies the desired identity;
- an owned exact record is updated only for TTL or ownership-comment drift;
- an unowned exact record is preserved and never claimed;
- only owned A/AAAA/NS records whose complete identity is absent from the
  desired set are deleted;
- unknown records (including TXT and human-owned records) are never touched.

The marker is the exact comment `micolab-managed`. A record changed by a human
that also changes its comments becomes unowned and is left alone. After
convergence the role re-reads the zone and asserts that the plan has zero
pending adds, updates, or deletes; there is no blind overwrite.
`records/add` uses `overwrite=false`.

## Firewall

`roles/baseline/templates/microlab-firewall.nft.j2` creates only the
`inet micolab_filter` table. It never flushes other tables. The
`micolab-firewall.service` oneshot unit applies it before `network.target`.

- loopback: all traffic
- established/related: accepted
- ICMP: accepted when `micolab_firewall_allow_icmp`
- SSH (`micolab_ssh_port`): admin CIDRs only
- DNS 53/udp and 53/tcp: admin + client + `micolab_dns_authoritative_only_cidrs`
- HTTP 80 and HTTPS 443: admin + client CIDRs (Caddy)
- DoT 853/tcp: admin + client + authoritative-only CIDRs when `micolab_dns_enable_dot`
- DoQ 853/udp: admin + client + authoritative-only CIDRs when `micolab_dns_enable_doq`
- forward: dropped; output: accepted
- final deny is rate-limited in the journal

`micolab_dns_authoritative_only_cidrs` (and its `_v6` counterpart) is the
explicit firewall-admitted, recursion-denied class. It is added to the DNS sets
only, never to the HTTP/HTTPS sets, and never to Technitium's recursion ACL.
This is what makes a remote recursion-denied probe possible: a firewall-denied
client would only time out, so it cannot prove REFUSED recursion.

The firewall does not open 3000, 4443, 5380, or 8053 externally. Caddy reaches
them over loopback. If the host has another firewall manager, reconcile it
manually; the role does not disable ufw/firewalld.

## Baseline checks

Before installing anything, baseline checks:

- host is in `microlab_management` and not `microlab_challenge`
- `ansible_host` is an IPv4 literal
- Debian major in `micolab_supported_debian_majors`
- architecture maps to `arm64`/`amd64` and matches inventory
- admin/client/recursion CIDRs are valid, strict networks, not `/0`
- authoritative-only CIDRs are valid, not `/0`, and do not overlap
  admin/client/recursion-allow networks
- A/AAAA values are valid addresses; no AAAA when IPv6 is disabled
- paths are absolute and non-overlapping; storage is not volatile and has
  `micolab_min_free_bytes`
- required packages and `libicu*` are installed
- `timedatectl NTPSynchronized=yes`
- artifacts exist on the controller and match pinned SHA256
- no unexpected listener owns 53, 5380, 80, 443, 853, or the SSH port;
  `systemd-resolved` on 53 is a hard failure
- admin secret is vaulted, at least 12 characters, not the bootstrap value

If any check fails, baseline does not apply the firewall or configure services. Its validation
directories and helper file may already have been written.

## DNS health and acceptance gates

After the DNS role's conditional mutations:

1. Handler restart runs only when settings/zone/records changed. This is the
   restart-persistence gate: the service is restarted before the following
   checks, so answers are proven to survive restart.
2. `dig` over UDP and TCP for every desired record must return
   `status: NOERROR`, the **AA flag set**, and the expected value. The role
   captures `+noall +answer +comments`, so `+short` cannot hide a
   non-authoritative answer.
3. The SOA answer must also have the AA flag and name `ns1.microlab.hnh`.
4. If IPv6 is disabled, each managed name must return an authoritative
   (AA, NOERROR, empty answer) NODATA for AAAA, and no role-owned AAAA record
   may exist.
5. The **controlled local recursion fixture** is validated before any
   Technitium setting or zone mutation. The required inventory values are
   `micolab_dns_fixture_upstream`, `micolab_dns_fixture_zone`,
   `micolab_dns_fixture_name`, and `micolab_dns_fixture_expected_ip`. The
   fixture zone must be distinct from `hnh` and outside `micolab_domain`; the
   name must be inside that zone. The role creates a conditional-forwarder
   zone for the fixture pointing at the local upstream, and gives that zone
   the exact same allowed-network ACL as the recursion policy. Technitium
   handles a Conditional Forwarder `FWD` record in its authoritative zone
   path, so without the zone query ACL a recursion-denied client could still
   receive the forwarded answer; the zone ACL makes the denied probe get
   `REFUSED` on the same fixture name. The global recursion ACL is separately
   proven for every authoritative-only network before mutation and after
   readback in `settings.yml`. Then a query for the fixture name through
   `127.0.0.1` must return `NOERROR`, the known expected A value, and **AA
   clear**. `SERVFAIL`, `NXDOMAIN`, a timeout, an authoritative `hnh` answer,
   or any override is not accepted as offline success. This proves the local
   recursion/forwarding path without internet access.
6. Remote probes are split into three explicit classes and use the same local
   fixture name:
   - `recursion-allowed`: source in admin/client/recursion-allow. The
     authoritative hnh query must return AA; the fixture name must return
     `NOERROR`, AA clear, and `micolab_dns_fixture_expected_ip`.
   - `recursion-denied`: source in `micolab_dns_authoritative_only_cidrs`.
     The authoritative query must return AA; the same fixture name must return
     `status: REFUSED`.
   - `firewall-denied`: source outside every firewall-admitted DNS network.
     The query must receive no reply (non-zero `dig` status, no RCODE).
   All three classes are required. This replaces the old impossible probe that
   expected a firewall-denied client to receive a REFUSED response and the old
   public `example.com` dependency. Probe hosts need `dig`
   (`bind9-dnsutils`) and must have the declared `source_address` assigned
   locally; `dig -b` makes the firewall/recursion class explicit.
   If probes are absent, the run fails unless
   `micolab_dns_accept_unverified_external_acl=true`. In that case the
   acceptance file records `external_acl_verified=false`, lists every
   unexecuted external gate, and local success is never presented as proof of
   external ACLs.
7. An optional connected public recursion check is separate and disabled by
   default (`micolab_dns_public_recursion_check=false`). It never contributes
   to the required local gates or to external ACL acceptance.
8. Only then is `/etc/resolv.conf` switched to `nameserver 127.0.0.1`. The
   backup is created and re-stat'ed with a SHA256 before the switch, so a
   first run can roll back too. `getent ahostsv4` must resolve all four
   service names. Failure restores the backup and verifies the restored file
   checksum against the backup; if that restore fails, the role says so
   explicitly instead of claiming rollback. The role refuses a symlinked
   resolver file (systemd-resolved/NetworkManager).

The machine-readable result is `/var/lib/microlab/dns-acceptance.json`
(schema 2):

```json
{
  "schema": 2,
  "zone": "hnh",
  "domain": "microlab.hnh",
  "primary_ns": "ns1.microlab.hnh",
  "admin_endpoint": "127.0.0.1:5380",
  "technitium_version": "<pin>",
  "local_gates": [
    "plain-dns-udp53-aa",
    "plain-dns-tcp53-aa",
    "soa-aa",
    "local-recursion-fixture-noerror",
    "settings-recursion-policy",
    "aaaa-absence-aa"
  ],
  "local_recursion": "fixture-noerror-aa-clear",
  "local_recursion_status": "NOERROR",
  "local_recursion_fixture": {
    "upstream": "127.0.0.1:5353",
    "zone": "fixture.microlab.internal",
    "name": "dialog.fixture.microlab.internal",
    "expected_ip": "192.0.2.80",
    "status": "NOERROR",
    "answers": ["192.0.2.80"],
    "aa": false,
    "zone_query_acl": ["10.0.0.0/8", "192.168.0.0/16"]
  },
  "fixture_upstream_verified": true,
  "public_recursion_check": false,
  "public_recursion_status": "not-run",
  "external_gates": [
    "external-authoritative-aa",
    "external-recursion-allowed",
    "external-recursion-denied",
    "external-firewall-denied"
  ],
  "external_acl_verified": true,
  "external_acl_override": false,
  "unexecuted_gates": [],
  "remote_probe_count": 3,
  "resolver_managed": true,
  "managed_records": ["..."]
}
```

The `verify` phase can consume this file; it is not a substitute for the
remote probes themselves.

## Role variable interface

### baseline

Required (usually from inventory): `micolab_management_group`,
`micolab_challenge_group`, `micolab_expected_os`,
`micolab_supported_debian_majors`, `micolab_expected_architecture`,
`micolab_admin_cidrs`, `micolab_client_cidrs`, `micolab_admin_cidrs_v6`,
`micolab_client_cidrs_v6`, `micolab_required_packages`,
`micolab_required_package_prefixes`, `micolab_min_free_bytes`,
`micolab_required_storage_path`, `micolab_ssh_port`,
`micolab_firewall_enable`, `micolab_staged_artifacts`,
`micolab_technitium_admin_password`.

Role defaults: `micolab_baseline_state_dir`,
`micolab_baseline_helper_dir`, `micolab_baseline_firewall_dir`,
`micolab_nft_binary`, `micolab_baseline_ss_command`.

### technitium_install

Consumes `micolab_staged_artifacts` entries named `technitium` and
`dotnet-aspnetcore-runtime`, plus `micolab_technitium_version`,
`micolab_technitium_runtime_major`, `micolab_technitium_install_dir`,
`micolab_technitium_config_dir`, `micolab_technitium_log_dir`,
`micolab_dotnet_install_dir`, `micolab_dotnet_binary`,
`micolab_technitium_user`, `micolab_technitium_group`,
`micolab_technitium_service_name`,
`micolab_technitium_admin_bind_address`,
`micolab_technitium_admin_port`.

Role defaults: `micolab_technitium_stage_dir`,
`micolab_technitium_release_marker`, `micolab_technitium_runtime_marker`,
`micolab_technitium_systemd_unit`, `micolab_technitium_logrotate_file`,
`micolab_technitium_health_retries`, `micolab_technitium_health_delay`.

### technitium_dns

Consumes `micolab_dns_addresses`, `micolab_dns_ipv6_enabled`,
`micolab_dns_ipv6_addresses`, `micolab_dns_zone`, `micolab_domain`,
`micolab_dns_primary_ns`, `micolab_dns_admin_email`,
`micolab_dns_recursion_allow_cidrs`, `micolab_dns_authoritative_only_cidrs`,
`micolab_dns_authoritative_only_cidrs_v6`, `micolab_dns_forwarders`,
`micolab_dns_allow_online_forwarders`, `micolab_dns_log_retention_days`,
`micolab_dns_stats_retention_days`, `micolab_dns_log_queries`,
`micolab_dns_manage_resolv_conf`, `micolab_dns_remote_probes`,
`micolab_dns_require_remote_probes`,
`micolab_dns_accept_unverified_external_acl`, `micolab_dns_extra_records`,
`micolab_dns_fixture_upstream`, `micolab_dns_fixture_zone`,
`micolab_dns_fixture_name`, `micolab_dns_fixture_expected_ip`,
`micolab_dns_fixture_manage_service`, `micolab_dns_fixture_listen_address`,
`micolab_dns_fixture_port`, `micolab_dns_public_recursion_check`.

Role defaults: `micolab_dns_api_base`, `micolab_dns_record_ttl`,
`micolab_dns_ns_ttl`, `micolab_dns_managed_comment`,
`micolab_dns_health_retries`, `micolab_dns_health_delay`,
`micolab_dns_restart_wait_retries`, `micolab_dns_restart_wait_delay`,
`micolab_dns_acceptance_file`, `micolab_dns_resolv_conf`,
`micolab_dns_resolv_backup`, `micolab_dns_admin_reverse_proxy_address`,
`micolab_dns_admin_real_ip_header`, `micolab_dns_fixture_ttl`,
`micolab_dns_fixture_service_name`, `micolab_dns_fixture_script_path`,
`micolab_dns_fixture_unit_path`, `micolab_dns_fixture_zone_marker`,
`micolab_dns_fixture_zone_state_path`.

### Shared role interfaces

- `micolab_caddy_enable_git`, `micolab_caddy_admin_upstream`,
  `micolab_caddy_forgejo_upstream`, `micolab_caddy_acme_trusted_roots`,
  `micolab_caddy_management_cidrs`, `micolab_caddy_dns_client_cidrs`,
  `micolab_caddy_admin_cidrs`
- `micolab_step_ca_domain`, `micolab_step_ca_url`,
  `micolab_trust_bundle_path` (consumed as
  `micolab_step_ca_trust_store_path`)
- `micolab_forgejo_domain`, `micolab_forgejo_http_addr`,
  `micolab_forgejo_http_port`
- `micolab_technitium_service_user`, `micolab_technitium_service_group`
  (aliases of the owned service account), `micolab_dns_dot_port`,
  `micolab_dns_doh_port` (loopback 8053), `micolab_dns_enable_dot/doh/doq`
- `micolab_verify_challenge_group`, `micolab_verify_tls_root`,
  `micolab_verify_required_services`

`playbooks/site.yml` maps the ports and paths where the other roles use
different variable names.

## Offline recursion fixture setup

The required local recursion gate does not use `example.com` or any public
resolver. A cold deployment needs one reachable local upstream that returns a
known non-authoritative answer for one dedicated test zone.

The default and recommended setup is the role-managed fixture:

1. Choose a fixture zone that is not `hnh` and is outside `micolab_domain`,
   for example `fixture.microlab.internal`.
2. Choose a name inside it, for example
   `dialog.fixture.microlab.internal`, and a documentation-only answer such as
   `192.0.2.80` (TEST-NET-1). The answer does not need to route anywhere.
3. Set in inventory:

   ```yaml
   micolab_dns_fixture_upstream: "127.0.0.1:5353"
   micolab_dns_fixture_zone: fixture.microlab.internal
   micolab_dns_fixture_name: dialog.fixture.microlab.internal
   micolab_dns_fixture_expected_ip: 192.0.2.80
   micolab_dns_fixture_manage_service: true
   micolab_dns_fixture_listen_address: "127.0.0.1"
   micolab_dns_fixture_port: 5353
   ```

The role installs and starts a tiny standard-library UDP responder as
`microlab-dns-fixture.service`. It listens only on IPv4 loopback, has AA clear,
and requires no internet, package download, container, or extra platform.
Before any Technitium setting or zone is mutated, the role queries it directly
and requires `NOERROR`, AA clear, and the exact expected answer. A changed
fixture responder script or systemd unit is restarted before that validation.
It then creates an empty conditional-forwarder zone for the fixture, reads its
complete record set, adds one FWD record marked with
`comments=micolab-managed:fixture-forwarder`, and repeats the check through
Technitium.

The fixture zone is only managed when that exact marker is present on its sole
apex FWD record. A pre-existing enabled `Forwarder` zone is not enough: an
unmarked FWD, multiple owned FWD records, or any conflicting/unowned forwarder
fails the run before the FWD set, the zone, or its query ACL is changed. The
role never replaces, deletes, or silently adopts an unrelated zone. To adopt a
genuinely pre-existing fixture manually, add the exact marker comment to its
single apex FWD record after verifying the target; the next run will then
converge that owned record. If the target changed, only the owned FWD's
forwarder is updated and its other fields are preserved.

Creating the zone is crash-safe:

1. The role writes its local creation-intent marker
   (`micolab_dns_fixture_zone_state_path`, default
   `/var/lib/microlab/dns-fixture-zone.state`) before the API call.
2. It creates the zone with `initializeForwarder=false`, so Technitium never
   creates an unmarked FWD record on the role's behalf.
3. It re-reads the complete FWD set and adds the owned record only after the
   configured upstream passed the direct AA-clear answer check.

If the run dies after zone creation but before the FWD record exists, the next
run may finish the empty zone only when the local marker is exactly the
`schema=1`, owner, and zone lines, in that order, with no duplicate,
conflicting, blank, or extra lines (each line is trimmed, so a trailing
newline is fine). The local file alone never claims a zone that has a
forwarder or a different identity, and an existing empty zone without that
exact marker fails closed. A crash after adding the FWD record leaves the
durable API marker, so it is a normal zero-change rerun.

If you already stage an equivalent local upstream externally, set
`micolab_dns_fixture_manage_service: false` and point
`micolab_dns_fixture_upstream` at its reachable `IPv4:port`. That upstream must
serve the same zone/name/answer with AA clear; the role still validates it
directly before mutation and through Technitium afterwards. No external
internet access is required for either path.

A connected public check is optional and separate. Set
`micolab_dns_public_recursion_check: true` only when the host has working WAN
recursion; it is recorded but never used as the required offline gate.

## Offline dependency list

Stage or preinstall, as appropriate:

- OS: Debian 12/13, arm64 or amd64, systemd, nftables, iproute2,
  bind9-dnsutils (`dig`), ca-certificates, tar, gzip, logrotate, `libicu*`
- Technitium portable release archive (pinned)
- ASP.NET Core runtime 10.x archive for arm64/amd64 (pinned)
- step-ca/step, Caddy, Forgejo artifacts for their roles (pinned separately)
- the offline recursion fixture above: either the role-managed stdlib service
  (no extra package) or an externally staged local upstream on a reachable
  `IPv4:port`

Technitium/runtime artifacts use controller-local paths. Step-ca/step archives
use target-local `file://` URLs by default; their CA material sources remain
controller-local. Caddy/Forgejo support explicit online-download opt-ins, and
step-ca supports remote artifact URLs only when enabled. Step-ca also runs
`apt` with `update_cache: false`; preinstall dependencies or provide an offline
package source. Baseline checks its required package set before installation.

## Local validation scope

Useful local checks from the repository root (recorded results and exact
validation scope are in [validation.md](validation.md)):

```sh
ansible-playbook -i inventories/example/hosts.yml playbooks/site.yml --syntax-check
python3 -m unittest discover -s tests
```

The unit suite includes mock-API reconciliation tests for settings ACLs and
zone records, first-run resolver backup/rollback tests, dig AA/REFUSED parsing
tests, first-match authoritative-only denial tests (including partial overlap,
deny-before-broad-allow, IPv6, and every configured network), fixture
responder/wiring tests, and static source/wiring checks. No live DNS server,
API, firewall, CA, or inventory host was contacted. The managed fixture is not
a claim that a real offline deployment was executed.

## Deployment procedure (not executed here)

Run from the repository root (the `ansible.cfg` inventory, roles, and
`playbooks/group_vars` symlink are relative to it), or pass an explicit
`-i`/`ANSIBLE_CONFIG`.

1. Copy `inventories/example`; fill the management SSH IP, OS/arch, admin and
   client CIDRs, four service IPv4 addresses, trust targets, lifecycle bound,
   real artifact pins, and the four required fixture values.
2. Stage the Technitium/runtime archives and compute their SHA256 values. If
   `micolab_dns_fixture_manage_service=false`, stage or start the equivalent
   local fixture upstream first.
3. Create the vaulted `micolab_technitium_admin_password` and durable service
   secrets. Follow [staged bootstrap](../README.md#deployment-order-and-first-bootstrap):
   the API token is created after DNS is up, and the short-lived enrollment
   token after step-ca is running. The site play does not automate these steps.
4. Review `micolab_dns_remote_probes`; add one probe for each of
   `recursion-allowed`, `recursion-denied`, and `firewall-denied`, with a
   `source_address` that belongs to that class. Add the recursion-denied
   network to `micolab_dns_authoritative_only_cidrs`. Or explicitly set
   `micolab_dns_accept_unverified_external_acl=true` and accept the recorded
   verification gap.
5. Run `ansible-playbook -i <inventory> playbooks/site.yml --ask-vault-pass`
   using the staged reruns above. After Forgejo is ready, create its disposable
   acceptance repository with an initial commit and register the SSH key before
   the final verification run. Phase labels are not supported phase tags.
6. Consume `/var/lib/microlab/dns-acceptance.json` and the `verify` role's
   report. Do not treat the run as accepted while
   `external_acl_verified=false`.

## Remaining gaps and limitations

- The `hnh` zone is internal. Upstream resolver configuration, conditional
  forwarding, delegation, and routing outside this host are operator-managed.
  Creating this zone does not make it publicly resolvable.
- Remote ACL acceptance is mandatory by default precisely because local queries
  bypass the external ingress path. A firewall-denied probe and a
  DNS-reachable recursion-denied probe are separate classes: the former proves
  the ingress drop, the latter proves Technitium's REFUSED recursion policy.
  If the operator acknowledges the gap, the run records it as unverified and
  lists the unexecuted gates rather than claiming success.
- No live host, API, firewall, or resolver was contacted while repairing this
  repository. All DNS behavior claims above are from local unit tests and
  static task inspection; deployment acceptance still requires the remote
  probes and the recorded `/var/lib/microlab/dns-acceptance.json`. The
  role-managed fixture is an acceptance aid on IPv4 loopback, not a
  general-purpose DNS service and not proof that a real cold offline host was
  tested.
- IPv6 is off by default. Enabling it requires AAAA data, IPv6 firewall/ACLs,
  and a TLS design that includes IPv6. `technitium_tls` rejects IPv6 SANs unless
  explicitly designed, so AAAA-only DNS is not the same as end-to-end IPv6.
- `technitium_tls` requires a vaulted API token and enrollment token; the DNS
  role rotates the admin password but does not create or store those tokens.
- Technitium TOTP 2FA is not automated. If 2FA is enabled on the admin account,
  the loopback login gate cannot complete; disable 2FA for the automation
  account or use a reviewed API-token workflow.
- The resolver switch requires a regular `/etc/resolv.conf`. A
  systemd-resolved/NetworkManager symlink or a listener on 53 fails closed.
  NetworkManager may rewrite the file after the switch; disable its DNS
  management first.
- On a successful live run, restart-persistence gates run when the DNS role
  mutates settings, the zone, or records. A no-op rerun does not restart the service; use an explicit
  maintenance restart plus the `verify` phase if a restart test is required on
  an unchanged configuration.
- DoQ is not enabled by the current TLS role. Enabling `micolab_dns_enable_doq`
  without a matching implementation only opens 853/udp, not a working service.
- DNSSEC signing, AXFR/IXFR policy beyond the admin ACL, and external
  monitoring are out of scope.
- The firewall role owns only its own nftables table; other firewall managers
  are not disabled. Reconcile them explicitly.
- Container/CI environments often fail the NTP synchronization gate and cannot
  bind port 53; those gates intentionally fail closed instead of weakening the
  production checks.
