# Validation status

**Experimental prerelease.** Local checks have passed; deployment acceptance
on a real management host remains outstanding. This document records prior
root-thread verification supplied for this checkout. The license/documentation
edit did not rerun the suite. These results are a historical record, not a
guarantee for later changes in the shared checkout.

## Recorded local checks

- Python unittest discovery: **258 tests passed, zero skipped**.
- Ansible syntax checks: `site.yml`, `backup.yml`, and `restore.yml` passed.
- Scoped offline Ansible lint: the command below passed. It excludes
  `var-naming` and `yaml`; this is not a full-project lint pass.

The recorded test command was:

```bash
CADDY_BIN=/tmp/opencode/caddy PATH=/tmp/opencode/ansvenv/bin:$PATH /tmp/opencode/ansvenv/bin/python -m unittest discover -s tests
```

Syntax-check commands for all three playbooks, from the repository root:

```bash
ansible-playbook --syntax-check -i inventories/example/hosts.yml playbooks/site.yml
ansible-playbook --syntax-check -i inventories/example/hosts.yml playbooks/backup.yml
ansible-playbook --syntax-check -i inventories/example/hosts.yml playbooks/restore.yml
```

The recorded lint command was:

```bash
/tmp/ansvenv/bin/ansible-lint --offline -x var-naming,yaml roles/caddy roles/forgejo roles/verify playbooks/backup.yml playbooks/restore.yml
```

The `/tmp` paths are examples of local verification tooling, not shipped
dependencies or required installation paths. Use equivalent tools in your own
environment: Python 3, PyYAML, Jinja2, Ansible Core, and ansible-lint; upstream
Caddy for rendered configuration validation; OpenSSL and Git for local
certificate/Git tests; bubblewrap, `unshare`, and `mount` with working Linux
user/mount namespaces for isolation and fault injection; and `setfacl` /
`getfacl` for ACL-preservation tests. Missing tools or namespace support can
cause skips on other machines; check the summary before comparing results.
`requirements.yml` declares no Galaxy roles or collections. Deployment also
requires the host packages and staged artifacts described in the
[README](../README.md) and role documentation.

## What the local tests establish

- Static assertions and template rendering check role wiring and configuration;
  the Caddy tests also validate rendered configuration with a real Caddy binary.
- Mock Technitium APIs exercise real Ansible task includes, state changes, and
  failure paths. Renewal-helper tests use disposable OpenSSL material and
  controlled operations; backup/restore tests exercise local helpers and guards
  with temporary state and simulated service control.
- CA preflight/material tests execute real Ansible includes. A bubblewrap
  namespace gives the logical target a different filesystem view from the
  controller, testing delegation and source/target selection. It is not a
  separate remote machine and does not exercise the full CA configure/service
  path or SSH transport.
- Local integration tests use real TLS listeners for DoT and Git smart HTTP,
  disposable trust roots, and real Git clone/commit/push/ref-check/delete
  operations. Git-over-SSH uses a fake SSH transport invoking real local Git
  server commands; it does not prove OpenSSH or Forgejo authentication.

No recorded local result proves a deployed Caddy/Forgejo/step-ca/Technitium
stack, real network policy, or client trust. Implemented checks in
`roles/verify` still need to be run against the intended environment.

## Inputs still required before deployment

The example inventory deliberately contains placeholders. Supply reviewed
version pins, SHA-256 checksums, and staged artifacts for Technitium, .NET,
step-ca, step CLI, Caddy, and Forgejo; the real management/SSH IP and user;
admin, client, and authoritative-only CIDRs; and the controlled local DNS
fixture values. Supply vaulted service/admin secrets, API/enrollment tokens,
and the PFX password, plus a disposable Git repository, credentials, operator
SSH key, and pinned SSH host key for acceptance.

Complete the offline root ceremony and separate root-key escrow, public root
fingerprint/trust distribution, intermediate material, and provisioner inputs
described in [CA recovery](ca-recovery.md). Root private material must remain
offline, outside the controller and management host. Provide real probe clients
with configured source addresses in the allowed, recursion-denied, and
firewall-denied networks, including the external HTTPS/DoH/DoT ACL cases.
Missing infrastructure or inputs are prerequisites, not completed validation.

## Real-host acceptance still outstanding

- First deployment and a second convergence run: confirm expected idempotence,
  DNS/DoH/DoT answers, service health, HTTPS and actual SSH Git operations,
  loopback-only listeners, and external firewall/application ACL behavior.
- Reboot the management host and repeat acceptance; systemd enablement alone
  does not establish reboot persistence.
- With WAN disconnected, prove cold local-fixture resolution and renewal
  through the local CA for Caddy and Technitium. Exercise renewal-window,
  outage/retry, and powered-off recovery behavior separately; a CA outage is
  not a successful offline renewal.
- After Technitium renewal/PFX publication and reload, compare the published
  leaf serial/fingerprint with the live DoT-served certificate and verify the
  chain and hostname. Confirm Caddy's served certificates also rotate.
- Prove root trust and hostname validation from actual intended clients,
  including their DNS and Git tooling, without disabling TLS verification.
- Create a quiesced backup and restore it to a clean, isolated target; verify
  state, credentials, trust, permissions, services, renewal, and client
  acceptance using [backup/restore](backup-restore.md). Local helper tests and
  restore dry-run do not establish this outcome.

Record real-host evidence before treating this as an accepted deployment.
See [certificate renewal](certificate-renewal.md) and [DNS](dns.md) for the
operational procedures. Live deployment, reboot, WAN-disconnected renewal,
and isolated restore have **not** been exercised in the recorded verification.
