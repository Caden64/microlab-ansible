# Role: `verify`

Experimental implementation; live deployment acceptance remains unexercised.
See [validation evidence and limits](../../docs/validation.md).

End-to-end acceptance checks for the MicroLab management host. The role runs
real queries; it does not report a green result for tests it did not execute.
The final debug output separates **executed** checks from **unexecuted** ones.

## Checks executed when the role runs

Run this role with `become: true` so it can read root-owned trust material and query systemd/loopback listeners.

- Naming is validated before any query (`tasks/targets.yml`). Service names
  are `<service>.<micolab_verify_service_domain>` (from `micolab_domain`,
  `microlab.hnh`); the NS query targets the authoritative zone apex
  `micolab_verify_zone` (from `micolab_dns_zone`, `hnh`). They are separate
  inputs and neither has a hard-coded fallback. The service domain must sit
  inside the zone; a set legacy `micolab_dns_zone_fqdn` must equal
  `micolab_domain`, and a set `micolab_dns_primary_ns` must be
  `ns1.<service domain>`, otherwise the role fails before querying. Every
  public site, CA/DoH/DoT/Git hostname, and the DoH probe name must be inside
  the service domain.
- `dig NS hnh` contains `ns1.microlab.hnh.`
- A records for `ns1.microlab.hnh`, `ca.microlab.hnh`, `dns.microlab.hnh`, and
  `git.microlab.hnh` match `micolab_verify_expected_a_records[<fqdn>]` (the
  shared group vars key it from `micolab_dns_addresses`) or else the inventory
  `ansible_host` IPv4 (no invented addresses).
- No AAAA records exist unless `micolab_verify_enable_ipv6` is true **and**
  explicit `micolab_verify_expected_aaaa_records` are supplied.
- Real TLS certificates for each public site, verified against the public
  step-ca root, with hostname and expiry checks; Caddy's local issuer is
  rejected.
- DoH at the exact `/dns-query` path returns a valid DNS JSON answer for the
  expected A address (catches path stripping and query loss).
- Local DoH and DoT (`tasks/encrypted_dns.yml`) query `git.microlab.hnh` and
  expect its `micolab_verify_expected_a_records` address. DoT uses a stdlib
  Python probe with strict CA and hostname validation against
  `micolab_verify_dot_host` (`dns.microlab.hnh`). Never opportunistic mode and
  no external `kdig` dependency.
- Real Git over HTTPS acceptance: clone the explicitly supplied disposable
  test repository with a username/token supplied through an askpass helper,
  create a unique branch, stage exactly `micolab-verify.txt`, commit, push,
  verify the remote ref, then delete the branch and prove it is absent. Every
  HTTPS operation (clone, push, ls-remote, anonymous check, and cleanup) passes
  `-c http.sslCAInfo=<micolab_verify_tls_root>` and
  `-c http.sslVerify=true`; a custom step-ca root does not need to be installed
  system-wide, and insecure verification is never used. No credential appears
  in argv or logs.
- Real Git over system OpenSSH port 22 acceptance: clone the same disposable
  repository with an operator-supplied key and pinned `known_hosts`, create a
  unique branch, stage exactly `micolab-verify.txt`, commit, push, verify, then
  delete. SSH clone/push is required for complete acceptance. No
  trust-on-first-use and no generated keys.
- Git success is recorded only after both remote branches are verified absent
  and the local askpass helper and workspace are removed. A remote deletion
  that cannot be proven fails acceptance with the exact branch names to delete
  (never a credential). Local credential and workspace removal is attempted
  even when remote cleanup fails, and is proven only by a post-removal stat;
  a failed removal or stat keeps the corresponding flag false.
- Anonymous access is checked against the declared
  `micolab_verify_git_visibility`: public must allow anonymous `ls-remote` and
  return HTTP 200; private must deny anonymous `ls-remote` and return
  401/403/404 for the web page.
- Real external-vantage ACL probes on delegated inventory hosts. For each of
  `dns_admin`, `ca_management`, `doh`, and `dot`, the role requires both an
  allowed and a denied probe and runs the actual command. Missing or
  one-sided evidence is not acceptance.
- External DoT probes are bound to their declared `source_address` (see
  below). An allowed probe queries only the DNS role's conditional-forwarder
  fixture (`micolab_dns_fixture_name`) and expects
  `micolab_dns_fixture_expected_ip`; it never needs WAN recursion. A denied
  probe collects two separately labelled pieces of evidence, and both must be
  DNS `RCODE=REFUSED`:
  1. **fixture zone query ACL** - the fixture name. Technitium serves FWD
     records through the authoritative zone path, so this REFUSED is the
     fixture zone's own query ACL. On its own it is **not** proof of global
     recursion policy.
  2. **global recursion ACL** - an RD=1 query for
     `micolab_verify_dns_recursion_denied_name` (default
     `microlab-recursion-acl-probe.invalid`), which must be outside the service
     domain, the `hnh` zone, and `micolab_dns_fixture_zone`. Only the global
     recursion policy can answer it. A denied source is refused before any
     upstream lookup, so this is offline; a wrongly recursion-allowed source
     would get SERVFAIL/NXDOMAIN/timeout instead and fail.
- Any other denied DoT outcome fails. A refused connection, connect
  timeout, unreachable route, TLS error, malformed response, or wrong answer is
  reported as inconclusive and fails; none of those proves an ACL dropped the
  client. The probe writes a structured `category`/`exit_code` status document
  instead of relying on stderr keyword matching.
- Every DoT probe must declare `source_address` and `access`. The probe
  creates a socket of the source's family, binds it to
  `(source_address, 0)` before connecting, reads back the connected socket's
  local address, and fails unless it equals the declared source (the shell
  re-checks the recorded `observed_source`). An invalid literal
  (`source_invalid`), an address not configured on the probe host
  (`source_unavailable`), a family the target does not have
  (`source_family`), or a mismatch (`source_mismatch`) fails and is never a
  denial. The management target is IPv4, so DoT sources must be IPv4. The allowed
  source must be in the recursion-allowed networks; the denied source must be
  in `micolab_dns_authoritative_only_cidrs` and must not be recursion-allowed.
  Both must be admitted by the baseline firewall's DNS networks for 853/tcp.
  A source outside those networks is firewall-denied, and its no-reply result
  is inconclusive rather than denial evidence. The role validates this against
  `micolab_admin_cidrs`, `micolab_client_cidrs`,
  `micolab_dns_recursion_allow_cidrs`, and
  `micolab_dns_authoritative_only_cidrs` before running any probe.
- Denied DoH is accepted only for the Caddy ACL's explicit HTTP 403. A curl
  transport failure (`000`) or any other status is not a denial. An allowed
  DoH response must contain the expected A address.
- Every internal loopback service (Forgejo 3000, step-ca 4443, Technitium DoH
  backend 8053, Caddy admin 2019) binds a loopback address only and never a
  wildcard. This is a strict socket check: Technitium's reverse-proxy ACL
  does not prove 8053 binds only loopback. The pinned release must satisfy it
  during deployment; current local tests do not prove this compatibility.
  DoT 853 is intentionally a non-loopback DNS listener: the baseline
  firewall admits it only from admin, client, and
  `micolab_dns_authoritative_only_cidrs`; it is not an open public listener and
  is tested separately.
- Required systemd units are enabled. This is a static reboot-persistence
  check; a live reboot remains untested.

## Required variables

| Variable | Description |
| --- | --- |
| `micolab_verify_git_repo` | **Disposable** Forgejo test repository path, e.g. `owner/verify-repo`, with at least one initial commit and an account allowed to push and delete branches. Never a production repository. |
| `micolab_verify_git_ssh_repo` | SSH repository path; defaults to `micolab_verify_git_repo`. |
| `micolab_verify_git_https_username` | Username for the disposable test repository over HTTPS. |
| `micolab_verify_git_https_token` | Token/password for the disposable test repository over HTTPS. Passed via an askpass helper environment, never argv or logs. |
| `micolab_verify_git_visibility` | `private` or `public`; anonymous access is asserted against this policy. |
| `micolab_verify_enable_ssh` | Must be true for complete acceptance (default true). SSH clone/push is not optional. |
| `micolab_verify_ssh_private_key` | Target path to the operator key that can push to the disposable test repository. |
| `micolab_verify_known_hosts` | Target path to the pinned `known_hosts` file. |
| `micolab_verify_tls_root` | Shared public step-ca root certificate PEM on the target and on every probe host (or supply per-probe `ca_file`). It is pinned explicitly on every Git HTTPS operation and does not need to be in the system trust store. |
| `micolab_verify_external_acl_probes` | Probe list; see below. Both allowed and denied probes are required for every ACL class. Every `dot` probe also needs `source_address` and `access` (`recursion-allowed` or `recursion-denied`) that match the configured networks. |
| `micolab_dns_fixture_name` / `micolab_dns_fixture_expected_ip` | The DNS role's conditional-forwarder fixture name and its known A answer. The DoT recursion probe uses these (via `micolab_verify_dns_fixture_name` and `micolab_verify_dns_fixture_expected_ip`). The fixture must not be in the authoritative `hnh` zone. |
| inventory group | A host in `micolab_verify_management_group` with `ansible_host` set to the SSH IPv4 address. Probe hosts must be other inventory hosts. |

## Optional variables

| Variable | Default | Description |
| --- | --- | --- |
| `micolab_verify_service_domain` | `{{ micolab_domain }}` (`microlab.hnh`) | Domain holding the service names. No fallback; empty fails. |
| `micolab_verify_zone` | `{{ micolab_dns_zone }}` (`hnh`) | Authoritative zone apex queried for NS. No fallback; empty fails. |
| `micolab_verify_ns_name` | `ns1.<service domain>.` | Required NS target. |
| `micolab_verify_service_names` | `[ns1, ca, dns, git]` | A/AAAA labels checked under the service domain. |
| `micolab_verify_management_group` | `microlab_management` | Inventory group holding the dedicated management host. |
| `micolab_verify_challenge_group` | `{{ micolab_challenge_group }}` (`microlab_challenge`) | Hosts in this group must not include the management host. |
| `micolab_verify_management_host` | `""` | Explicit management host; otherwise the first group member. |
| `micolab_verify_expected_a_records` | `{}` | FQDN-to-IPv4 overrides; otherwise the inventory SSH IPv4 is used. |
| `micolab_verify_expected_aaaa_records` | `{}` | Required explicit values when IPv6 is enabled. |
| `micolab_verify_enable_ipv6` | `false` | Must be explicitly true before AAAA records are accepted. |
| `micolab_verify_dns_server` | `127.0.0.1` | DNS server queried for A/NS. |
| `micolab_verify_dns_port` | `53` | DNS server port. |
| `micolab_verify_https_port` | `443` | Caddy HTTPS port. |
| `micolab_verify_public_sites` | `ca/dns/git.<service domain>` | Sites whose certificates are verified. |
| `micolab_verify_ca_host` | `ca.<service domain>` | CA management hostname for external probes. |
| `micolab_verify_doh_host` | `dns.<service domain>` | DoH hostname. |
| `micolab_verify_doh_path` | `/dns-query` | Exact DoH path. |
| `micolab_verify_dot_host` | `dns.<service domain>` | DoT certificate/SNI hostname, independent of the queried fixture name. |
| `micolab_verify_dot_port` | `853` | DoT port. |
| `micolab_verify_dns_fixture_name` | `{{ micolab_dns_fixture_name }}` | Recursive fixture query name used by DoT probes. |
| `micolab_verify_dns_fixture_expected_ip` | `{{ micolab_dns_fixture_expected_ip }}` | Expected A answer for the DoT fixture query. |
| `micolab_verify_dns_fixture_zone` | `{{ micolab_dns_fixture_zone }}` | Fixture forwarder zone; required so the global-recursion name can be proven outside it. |
| `micolab_verify_dns_recursion_denied_name` | `microlab-recursion-acl-probe.invalid` | Out-of-zone RD=1 name a denied DoT source must get REFUSED for (global recursion ACL evidence). |
| `micolab_verify_dot_probe_stage_path` | `/tmp/microlab-dot-probe.py` | Where the DoT probe is staged on probe hosts; removed afterwards. |
| `micolab_verify_dns_authoritative_only_cidrs` | `{{ micolab_dns_authoritative_only_cidrs }}` | Firewall-admitted but recursion-denied source class. |
| `micolab_verify_dns_recursion_allowed_cidrs` | admin + client + `micolab_dns_recursion_allow_cidrs` | Recursion-allowed source class. |
| `micolab_verify_dns_firewall_admitted_cidrs` | admin + client + authoritative-only | DNS networks admitted by the baseline firewall (53 and 853). |
| `micolab_verify_dot_connect_host` | `127.0.0.1` | DoT connection address; certificate is checked against `micolab_verify_dot_host`. |
| `micolab_verify_enable_dot` | `true` | Execute the real DoT probe. |
| `micolab_verify_git_host` | `{{ micolab_forgejo_domain }}` or `git.<service domain>` | Forgejo hostname. |
| `micolab_verify_git_ssh_repo` | `{{ micolab_verify_git_repo }}` | SSH repository path. |
| `micolab_verify_enable_ssh` | `true` | Must stay true for complete acceptance. |
| `micolab_verify_ssh_port` | `22` | System OpenSSH port. |
| `micolab_verify_git_test_root` | `/var/lib/microlab/verify-git` | Private workspace for the disposable clone/push test. Must be an absolute, site-specific leaf (at least three path components, no `..`); it is removed recursively after the run. |
| `micolab_verify_accept_unexecuted_git_acceptance` | `false` | Explicit override that skips clone/push and records a noncomplete result. Never a pass. |
| `micolab_verify_external_acl_probes` | `[]` | External probe list; both allowed and denied probes are required for `dns_admin`, `ca_management`, `doh`, and `dot`. |
| `micolab_verify_accept_unverified_external_acl` | `false` | Explicit override that records external ACLs as noncomplete. Never a pass. |
| `micolab_verify_external_probe_timeout` | `15` | Per-command probe timeout in seconds. |
| `micolab_verify_acceptance_file` | `/var/lib/microlab/verify-acceptance.json` | Machine-readable acceptance record written on the management host. |
| `micolab_verify_loopback_ports` | map | Loopback-only ports to assert (8053/3000/4443/2019; DoT 853 is not loopback-only). |
| `micolab_verify_required_services` | `[caddy, forgejo, step-ca, dns]` | Units that must be enabled. Override the DNS unit name if your site role uses another name. |
| `micolab_verify_management_cidrs` | `[]` | Expected management policy used when selecting probe hosts. |
| `micolab_verify_dns_client_cidrs` | `[]` | Expected DoH client policy used when selecting probe hosts. |
| `micolab_verify_admin_cidrs` | `[]` | Expected admin policy used when selecting probe hosts. |

## External ACL probe list

Each item is an actual command run on the named inventory host (the role uses
`delegate_to`), not a fabricated attestation:

```yaml
micolab_verify_external_acl_probes:
  - { name: dns-admin-allowed, host: lab-client, check: dns_admin, expect: allowed }
  - { name: dns-admin-denied,  host: challenge-host, check: dns_admin, expect: denied }
  - { name: ca-allowed,        host: lab-client, check: ca_management, expect: allowed }
  - { name: ca-denied,         host: challenge-host, check: ca_management, expect: denied }
  - { name: doh-allowed,       host: lab-client, check: doh, expect: allowed }
  - { name: doh-denied,        host: challenge-host, check: doh, expect: denied }
  - { name: dot-allowed,       host: lab-client, check: dot, expect: allowed,
      source_address: <client-ip-configured-on-lab-client>, access: recursion-allowed }
  - { name: dot-denied,        host: auth-only-client, check: dot, expect: denied,
      source_address: <authoritative-only-ip-configured-on-that-host>, access: recursion-denied }
```

`check` is one of `dns_admin`, `ca_management`, `doh`, or `dot`; `expect` is
`allowed` or `denied`. A probe host must be an inventory host that is not the
management host, and it needs `curl`, `python3`, and the shared CA root (or a
per-probe `ca_file`). The role fails unless every class has both an allowed and
a denied probe and every executed probe matches its expectation.

Every `dot` probe must declare `source_address` and `access`. The source is
checked against the configured networks before any probe runs: `allowed` must
be in the recursion-allowed set and `denied` must be in
`micolab_dns_authoritative_only_cidrs` (and outside recursion-allowed). Both
must be firewall-admitted for 853/tcp. Do not use the delegated host's default
route as an implicit source: the role passes `source_address` to the probe
(`SOURCE_ADDRESS` in the task environment, `--source-address` on the probe) and
the socket is bound to it, so the address must actually be configured on the
probe host.

For `dot`, a `denied` probe passes only when the target returns a positive DNS
`RCODE=REFUSED` both for `micolab_dns_fixture_name` (labelled
`fixture_zone_query_acl`) and for the out-of-zone
`micolab_verify_dns_recursion_denied_name` (labelled `global_recursion_acl`),
from the bound source address. The fixture REFUSED alone only proves the
fixture zone's query ACL, because Technitium answers FWD records through the
authoritative path; the out-of-zone query is what exercises the global
recursion ACL. Querying `ns1` in the authoritative `hnh` zone would answer even
an authoritative-only client, so it is never used for denial.

What this does **not** prove: the configured value of `recursion` /
`recursionNetworkACL`. That configuration readback is done by the
`technitium_dns` role (`tasks/settings.yml`, readback after mutation and
restart), not by this role, which has no Technitium API token. The two are
separate evidence: the readback shows what is configured; the DoT probe shows
the behaviour one declared source actually observed. Neither probe proves the
behaviour for sources outside the declared ones.
Connection refused, connect timeout, unreachable routes, TLS errors, malformed
responses, and wrong answers are classified separately and fail as
inconclusive. This role does not attempt to infer an ACL from a firewall DROP,
because it cannot prove source-specific isolation from a single delegated
probe. Record such a result as a network limitation, not acceptance.

For `doh`, a `denied` probe passes only with the Caddy ACL's explicit HTTP 403.
A curl transport failure (`000`) is not denial evidence. An `allowed` DoH
response must parse as DNS JSON with status 0 and contain the expected A
address.

### Technitium admin proxy trust

The DNS role configures Technitium to see the real client address rather than
Caddy's loopback hop. It sets `webServiceReverseProxyAddresses=127.0.0.1`
exactly (replacing, never merging arbitrary proxy networks) and
`webServiceRealIpHeader=X-Real-IP`. Caddy connects to the admin upstream over
IPv4 loopback and overwrites `X-Real-IP`; the DNS role reads both settings back
after the mutation and after the persistence restart, so a drift or an
over-broad trust list fails the DNS role instead of silently degrading logging.

This is the current role interface (`micolab_dns_admin_reverse_proxy_address`,
`micolab_dns_admin_real_ip_header`, and `docs/dns.md`), not a live-acceptance
claim. In particular, it does not prove a particular deployed host: if an older
DNS role version is in use, or the readback has not run, do not report admin
source logging as verified. Caddy still enforces `micolab_caddy_admin_cidrs`
either way, so proxy trust affects source logging, not access.

## Unexecuted acceptance checks and overrides

The role deliberately reports these as unexecuted rather than passing them:

- **Reboot persistence**: systemd enablement is checked, but no reboot is
  performed.
- **Offline ACME renewal**: requires exercising the renewal window with WAN
  access disconnected and the local step-ca running. A stopped issuing CA
  cannot renew certificates; an outage test instead checks failure/retry and
  recovery. The role only checks the currently served chain and expiry.
- **Restore acceptance**: requires an isolated target and a validated backup;
  `playbooks/restore.yml` defaults to dry-run. See [backup/restore](../../docs/backup-restore.md).
- **Git and external ACL acceptance when overridden**: setting
  `micolab_verify_accept_unexecuted_git_acceptance=true` or
  `micolab_verify_accept_unverified_external_acl=true` skips the real check.
  The acceptance record then says `overall: noncomplete` and names the
  override. An override is never reported as a pass.
- **External ACL denial that the network cannot distinguish**: a DoT timeout
  or refused connection without a positive DNS REFUSED, and a DoH result other
  than HTTP 403, remain noncomplete. A source outside the firewall-admitted DNS
  networks is never counted as a recursion denial. The role does not invent an
  ACL proof from a transport failure.

The acceptance record is written to `micolab_verify_acceptance_file` with the
Git state, visibility, remote cleanup and local removal states, external probe
list and results, and the remaining unexecuted checks.
