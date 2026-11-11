# MicroLab Ansible

Experimental Ansible deployment for a dedicated Debian 12/13 management host
(amd64 or arm64), separate from challenge workloads. It configures a host
firewall, Technitium DNS, an internal step-ca intermediate CA, Caddy, Forgejo,
and acceptance checks. This is a locally tested implementation; a live
management-plane deployment has not been validated. See
[validation evidence and limits](docs/validation.md).

The authoritative zone is **`hnh`**; the service domain is
**`microlab.hnh`**. The zone publishes `ns1.microlab.hnh` and the `ca`, `dns`,
and `git` service A records. IPv6 and AAAA records require explicit inputs.
Caddy serves HTTPS for the CA, DNS console/DoH, and Forgejo. Technitium serves
plain DNS and native DoT; Forgejo uses system OpenSSH on port 22.

## Scope and layout

- [playbooks/site.yml](playbooks/site.yml): serialized management-host deployment.
- [inventories/example](inventories/example/hosts.yml): placeholder inventory;
  supply real host addresses and site policy before use.
- [group_vars/all.yml](group_vars/all.yml): shared interface and defaults.
- [DNS and firewall](docs/dns.md): baseline checks, Technitium installation,
  zone/record reconciliation, resolver changes, and network acceptance.
- [CA recovery](docs/ca-recovery.md) and [certificate renewal](docs/certificate-renewal.md).
- Role interfaces: [step-ca](roles/step_ca/README.md),
  [Technitium TLS](roles/technitium_tls/README.md),
  [Caddy](roles/caddy/README.md), [Forgejo](roles/forgejo/README.md),
  [verify](roles/verify/README.md).
- [Backup and isolated restore](docs/backup-restore.md).

Site configuration changes target `microlab_management`. Explicitly configured
external probes also run on named inventory hosts. Verification creates and
removes branches in an operator-provided disposable Forgejo repository.
NAT, routing, upstream DNS delegation, hypervisor setup, and challenge workload
deployment remain operator responsibilities.

## Prerequisites and inputs

Run from this directory so `ansible.cfg` and the playbook's shared variables
resolve correctly. The controller needs Ansible Core 2.16+, Python 3, and
OpenSSL for CA source validation; there are no Galaxy dependencies in
[requirements.yml](requirements.yml). Targets need Python 3, systemd, sudo
access, synchronized time, suitable local storage, and the packages checked by
baseline. Preinstall the required packages or provide a usable offline package
source: step-ca additionally runs `apt` with `update_cache: false` to ensure
`ca-certificates`, `curl`, `openssl`, and `tar` are present. Caddy and Forgejo
check their command dependencies rather than installing them. Include `git-lfs`,
OpenSSH, and `util-linux` (`findmnt`) for Forgejo and acceptance.

Copy the example inventory into a private site inventory and replace every
`REPLACE_` value. Use Ansible Vault or an external secret source; never commit
real credentials, private keys, site inventories, or backup archives. Consult
[inventories/vault.yml.example](inventories/vault.yml.example) for loading
secrets; that example is not loaded automatically.

| Input | Interface / requirement |
| --- | --- |
| Host and topology | `microlab_management`, a literal SSH IPv4 in `ansible_host`, admin/client CIDRs, expected OS/architecture, storage and powered-off lifecycle bound. Keep management and challenge groups disjoint. |
| DNS | `micolab_dns_addresses` for `ns1`, `ca`, `dns`, `git`; four `micolab_dns_fixture_*` upstream/zone/name/expected-IP values; recursion policy and real remote probe hosts/source addresses. |
| Technitium/runtime pins | Exact version and SHA-256-pinned controller archives in `micolab_staged_artifacts`, entries `technitium` and `dotnet-aspnetcore-runtime`. |
| CA pins and material | `microlab_step_ca_version`, `_checksums`, `microlab_step_cli_version`, `_checksums`; target-local archives; absolute controller paths for the public root, intermediate certificate, and encrypted intermediate key; pinned root fingerprint, key password, and JWK provisioner material. The root private key stays offline. |
| Caddy/Forgejo pins | Exact versions, architecture checksums and controller artifacts through their role variables or matching `caddy` / `forgejo` staged entries. |
| Trust | `micolab_trust_targets`, public root bundle, and root trust on clients/probe hosts. The CA role installs the public root on the management host; it does not enroll arbitrary remote consumers. |
| Durable secrets | Technitium admin password and PFX password; Forgejo's four persistent secrets and admin username/email/password. See role READMEs for constraints. |
| Initial TLS enrollment | Technitium Settings: Modify API token plus a short-lived single-use CA enrollment token; see staged bootstrap below. |
| Git acceptance | Existing disposable writable `owner/repo`, visibility policy, HTTPS credentials, and SSH key registered through Forgejo plus pinned `known_hosts`. Supply the target-side paths expected by verify. |
| External acceptance | DNS remote probe classes and verify's allowed/denied CA/admin/DoH/DoT probes from real networks, with trust roots on those hosts. Overrides record incomplete acceptance. |

The spelling is part of the current interface: CA/TLS roles use canonical
`microlab_` variables; shared configuration and the other roles use `micolab_`.
Documented aliases connect selected values. Both prefixes are intentional here;
changing the spelling indiscriminately breaks configuration.

Artifact locations differ: Technitium/runtime, Caddy, and Forgejo use
**controller-local** source paths and transfer the artifacts. CA certificate
and key `*_src` paths are also controller-local and validated there before
copying. In contrast, step-ca/step archives use `get_url` **on the target**:
the default `file:///srv/microlab/artifacts` refers to the management host's
filesystem. Stage those archives there separately. Remote CA artifact URLs and
Caddy/Forgejo release downloads require their explicit opt-in flags; offline
staging does not remove package prerequisites.

## Deployment order and first bootstrap

[site.yml](playbooks/site.yml) runs baseline validation/firewall, Technitium
installation, DNS configuration and acceptance, step-ca, Caddy with CA+DNS
vhosts (Git disabled and DoH probing deferred), Technitium TLS, Caddy's DoH
readiness check, Forgejo, final Caddy with Git enabled, and verify. Handlers are
flushed between phases. These phase names are task labels, not supported tags.

A fresh host needs staged operator input. The site play does not create the
Technitium API token, mint an enrollment token automatically, create a Forgejo
acceptance repository, or register its SSH key.

1. Prepare the host, complete inventory/pins/vault, and initialize the CA
   material offline using [CA recovery](docs/ca-recovery.md). Set
   `microlab_step_ca_initial_deploy: true` only for the initial CA deployment.
   Choose the disposable repository's future `owner/repo` identity in advance
   for baseline's input validation.
2. Run the site play. With missing TLS tokens it stops at the TLS phase after
   earlier phases have made changes. Check the recorded failure before
   continuing. Once step-ca has successfully initialized its database, remove
   the initial-deploy flag, even if a later phase failed. For an interrupted
   CA initialization, follow the CA recovery procedure instead of retrying blindly.
3. Create a Technitium API token through its loopback API using an authenticated
   admin session and Settings: Modify permission. On the CA host, run
   `/usr/local/sbin/step-ca-technitium-token dns.microlab.hnh`; the helper prompts
   for the JWK provisioner password. Store/pass the API token and enrollment
   token through protected inputs and rerun promptly (the enrollment token has
   a ten-minute lifetime). Remove the single-use token after successful enrollment.
4. The next run can reach Forgejo and final Caddy, then stops at verify if its
   repository/credentials are not ready. Through Forgejo, create the disposable
   repository with an initial commit, register the acceptance user's SSH public key, and provide
   HTTPS credentials, a target-side SSH private key, and pinned host keys.
   Rerun for acceptance; verify commits, pushes, verifies, and deletes unique
   test branches. Read its report and any cleanup failure.

```bash
# Operator deployment command, after reviewing the steps above.
ansible-playbook -i inventories/<site>/hosts.yml playbooks/site.yml --ask-vault-pass
```

Reruns repeat the ordered play; there is no automatic pause/resume bootstrap
workflow. A failed run may leave earlier services configured. Do not bypass a
failed gate or use an acceptance override to claim a complete deployment.
Caddy issues directly through
`https://127.0.0.1:4443/acme/acme/directory`, provisioner `acme`, with root and
IP-SAN verification. Issuance does not depend on Caddy proxying its own CA URL.

## Network policy

Baseline manages its own nftables table; review coexistence with other firewall
managers. Default ingress policy is:

| Port | Service | Admitted source networks |
| --- | --- | --- |
| 22/tcp | System OpenSSH / Git SSH | Admin |
| 53/udp,tcp | Technitium DNS | Admin, client, authoritative-only |
| 80,443/tcp | Caddy | Admin and client; route ACLs further restrict CA and admin paths |
| 853/tcp | Native Technitium DoT | Admin, client, authoritative-only; recursion ACL still applies |
| 3000,4443,2019/tcp | Forgejo HTTP, step-ca, Caddy admin | Loopback |
| 5380,8053/tcp | Technitium admin / HTTP DoH backend | Caddy uses loopback; firewall and application ACLs must prevent remote access |

Technitium lacks a separate DoH/DoT bind-address setting. Its reverse-proxy
ACL is not proof of a loopback socket bind; verify currently requires a
loopback-only 8053 listener. That compatibility requirement must be checked on
the pinned release during deployment. DoQ is not implemented by the TLS role.
See [DNS limitations](docs/dns.md) and [verify](roles/verify/README.md).

## Validation and recovery

[docs/validation.md](docs/validation.md) records the local checks and their
scope. Local unit/integration tests, syntax checks, and the documented limited
lint scope do not prove live DNS/API behavior, firewall reachability, certificate
issuance/renewal, or service recovery. Live deployment, reboot persistence,
WAN-disconnected renewal with the local CA running, and isolated restore remain
unexercised. Renewal cannot succeed while the issuing CA is stopped.

Use [backup/restore](docs/backup-restore.md) for quiesced target-local backups,
protected archives, isolated validation, explicit restore confirmation, and
rollback requirements. Off-host replication and encryption at rest need an
operator-managed process.

## License

[MIT](LICENSE). Third-party binaries and dependencies retain their own licenses.
