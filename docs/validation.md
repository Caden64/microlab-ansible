# Validation status

**Experimental prerelease.** Local checks have passed; deployment acceptance
on a real management host remains outstanding. Historical full-suite results
and current onboarding checks are recorded separately below. Neither is a
guarantee for later changes in this shared checkout.

## Current onboarding checks (2026-11-13)

`tests/test_setup_experience.py`: **10 passed, zero skipped**. These run the
actual launcher in disposable copied checkouts with temporary fresh and filled
inventories. Synthetic ELF/archive fixtures replace publisher downloads;
mock Vault, inventory and Ansible subprocesses replace encryption and remote
execution. The fixtures contain no real keys and contact no inventory targets.

They establish the five command/help interfaces, fresh same-subnet setup,
byte-preserving filled-inventory/Vault reuse, artifact staging/rerun preservation,
required specific admin identity, pre-mutation CA checkpoint, bootstrap to
deploy/verify command routing, failure exit propagation and local-only status.
The fresh-directory case exercises setup → artifacts → bootstrap → deploy →
verify → status. A successful mock verify **does not prove acceptance**.

```bash
python -m unittest discover -s tests -p test_setup_experience.py
```

Syntax checks passed for `bootstrap.yml`, `deploy.yml` and `verify.yml`, using
only `inventories/example/hosts.yml`; no target connection was made.

The broader focused run also passed: **46 setup/artifact tests**
(`test_*setup*.py`, including the 10 onboarding cases above) and **9 staged
workflow tests** (`test_install_workflow.py`), zero skipped. The workflow tests
use local mock roles and disposable state, not inventory targets. The historical
258-test full suite below was not rerun for this documentation/test change.

Current launcher limitations: `status` does not retrieve remote reports or
unlock encrypted configuration; it labels remote state UNVERIFIED. Deploy
stage selection currently relies on both TLS tokens being present, so clearing
a consumed enrollment token selects bootstrap again. An explicit resume stage
or enrollment-aware selection remains needed. Do not keep consumed/dummy tokens
to work around selection. The wrapper exposes no artifact `--offline`/`--check`
flags; those belong to the standalone artifact module. See
[fresh-clone onboarding](fresh-clone.md) for the actual command contract.

## Historical full-suite checks

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

## Installation inputs and later acceptance inputs

The example inventory deliberately contains placeholders. Reuse an already
filled private inventory; setup must not overwrite it. This site's two hosts
are infra `10.72.78.73` and rCTF/microVM `10.72.78.72`, both reachable by players
on `10.72.78.0/24`. The admin workstation `/32` or protected VPN CIDR remains
unknown and required. Client access is not CA/DNS admin permission. A stable
DHCP reservation is sufficient; no router or host static-network rewrite is
needed. Those addresses belong in site inputs, not universal role defaults.

Installation needs reviewed versions, checksums and controller artifacts for
Technitium, .NET, step-ca, step CLI, Caddy and Forgejo; actual SSH identity,
architecture, client/admin CIDRs, storage/time policy and local DNS fixture
values. The staged artifact workflow supplies controller CA archive paths for
Ansible to copy; legacy `site.yml` can also use the existing target-local
artifact interface. A downloaded/validated artifact is not service acceptance.

The offline root ceremony, separate root-key escrow, public root fingerprint,
intermediate material and provisioner inputs remain operator work. See
[CA recovery](ca-recovery.md). Root private material stays offline, outside
both infra and the controller. Durable secrets and the TLS API/enrollment
handoff are still required; no unknown tokens are created by setup.

A disposable Git repo/credentials/SSH identity and real external ACL probe
vantages are **later full-acceptance inputs**, not a requirement to provision
extra physical installation hosts. Real source addresses and policy remain
necessary to prove denial. On this shared client subnet some denial classes
have no supplied vantage; they remain pending. Do not change client policy or
invent five networks to make the installation appear accepted.

Staged `bootstrap.yml` records `credential-checkpoint`; `deploy.yml` records
`local-ready` only after its local checks. `verify.yml` requests external DNS,
HTTPS/DoH/DoT and Git acceptance and refuses incomplete-acceptance overrides.
Missing probes are never passed tests. These playbooks target one infra host;
the separate rCTF/microVM host is not configured by them.

The CLI selects these installation stages explicitly with `deploy --stage
bootstrap` and `deploy --stage services`. After first enrollment, clear the
consumed enrollment token and keep using `--stage services`; a missing one-use
token does not prove the target needs bootstrap. Local CLI regression tests
exercise this handoff with mocked playbook execution, not a live certificate.

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

## CTF challenge tooling (2026-11-19)

Added with no live deployment exercised: the `./microlab challenges`
commands, `scripts/microlab_challenges.py`, `playbooks/challenges.yml`, the
`rctf_challenges` role, the `challenges/` definitions and
`config/challenges.lock.json`. What has actually passed locally:

- `microlab_challenges.py` `check`/`manifest`/`artifacts` modes exercised
  against the example inventory with fixture images: markers fail closed,
  digest/size/diskMiB drift fails closed, rebuild re-pins require
  `--allow-update`, and the manifest fill produces the recorded output.
- `challenges.yml` parses and passes `ansible-playbook --syntax-check` with
  only `inventories/example/hosts.yml`; no target connection was made.

Not exercised: the Traefik download (the pin reuses the rCTF fork's reviewed
v3.7.15 sha256 pair), any play against a real NUC or Pi, the rCTF admin API
login/upsert/readback, DNS wildcard verification, Caddy reload, and the
acceptance probes in [challenges.md](challenges.md). A green playbook is not
challenge acceptance.
