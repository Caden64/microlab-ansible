# From checkout to installation

If the rCTF workload host still needs its operating system, first follow
[Install Debian on the rCTF host](rctf-debian-install.md). It covers the full
USB-to-SSH procedure for `10.72.78.72`; the infra Pi stays at `10.72.78.73`.

Use the existing checkout if you already have it. Run commands in the directory
containing `ansible.cfg`, `roles/` and `inventories/`.

```bash
cd /home/caden64/projects/microlab/ansible
./microlab --help
./microlab setup --help
./microlab artifacts --help
./microlab deploy --help
./microlab verify --help
./microlab status --help
```

The [advanced reference](setup.md) retains detailed manual inputs and the
legacy `site.yml` workflow. Its intentional assertion failures are not the new
bootstrap procedure. The CLI supports `--inventory FILE` before or after the
command. Its default is `inventories/site/hosts.yml`.

## Two hosts and the inputs you actually need

| Input | This site | What to do |
| --- | --- | --- |
| Infra SSH IPv4 | `10.72.78.73` | One Pi runs Technitium, step-ca, Caddy and Forgejo; DHCP reservation is sufficient. |
| rCTF + microVM IPv4 | `10.72.78.72` | Separate workload host; not a target for this repo's infra deploy. |
| Player/client CIDR | `10.72.78.0/24` | Client DNS/web policy, **not** an admin grant. |
| Admin source CIDR | **Unknown, required** | Supply your actual admin workstation `/32` or protected VPN CIDR. Never guess it or use `.73` as your operator identity. |
| SSH user/key, architecture | Site-specific | Supply the actual infra login and `arm64` or `amd64`. A Pi's architecture still needs confirmation. |
| Names and backend ports | Repository defaults | Keep `hnh`, `microlab.hnh` and existing loopback backend ports. |
| DNS service A records | Infra `.73` for all four | `ns1`, `ca`, `dns`, `git.microlab.hnh` share the same address. |
| Public root/intermediate, fingerprint, escrow | Operator supplied | Follow the offline CA procedure; never place the root private key on infra or the controller. |
| Service secrets and enrollment inputs | Operator supplied | Store in Vault or a protected external source. No automatic CA ceremony or token creation is promised. |

Do not provision additional physical probe hosts or five networks to install.
The admin `/32` can be inside the client `/24`. Players reaching an address
must not gain CA/DNS administration. Infra self-traffic for HTTP01 and local
Git checks must remain allowed. Denial acceptance later needs genuine source
vantages with the appropriate policy; missing vantages stay unexecuted.

## Prepare the infra host once

Deploy checks these on the infra host and stops at its first validation step
if any is missing; it does not install OS packages or fix the clock for you.
On the **infra host** (`10.72.78.73`), while its package mirror still works:

```bash
sudo apt-get update
sudo apt-get install python3 sudo openssh-server ca-certificates curl \
  bind9-dnsutils knot-dnsutils git git-lfs gzip iproute2 logrotate nftables \
  openssl tar util-linux libicu-dev
timedatectl show -p NTPSynchronized --value   # must print: yes
sudo ss -lntup | grep -E ':(53|80|443|853|5380)\s' || echo 'service ports free'
```

Port 53, 80, 443, 853 or 5380 already in use by another program (for example
`systemd-resolved` on 53) must be resolved first. Your SSH user needs working
`sudo`. The [advanced reference](setup.md) covers account creation and storage.

## Prepare locally and keep your inventory

If you already filled inventory, reuse it:

```bash
./microlab setup --inventory inventories/site/hosts.yml
./microlab status --inventory inventories/site/hosts.yml
```

Substitute your existing inventory path if different. Setup retains existing
values even when flags supply alternatives. Missing host fields can require a
reviewed local merge, preserving an exact private backup; unknown keys remain.
Do not copy `inventories/example` over your inventory. Unresolved `REPLACE_`
values in an imported inventory may still require private manual correction.

For a fresh site, this command supplies the known addresses and asks for the
remaining SSH identity, architecture and **actual admin source** interactively:

```bash
./microlab setup --infra-ip 10.72.78.73 --rctf-ip 10.72.78.72 \
  --client-cidr 10.72.78.0/24
```

You may also supply `--ssh-user`, `--ssh-key`, `--arch` and repeatable
`--admin-cidr` explicitly. No real admin address is supplied by this guide.
Setup uses protected Vault input, generates missing durable application secrets,
and adds separate `setup.yml` / `setup-vault.yml` group-var files. It does not
reset your existing secrets. Review its 24-hour powered-off budget default
against your certificate lifetime and renewal policy before deploying.

Review non-secret values in your private `hosts.yml` and
`group_vars/microlab_management/main.yml`. Use `ansible-vault edit` for an
existing encrypted secrets file. Never print decrypted inventory, use `--diff`
with secrets, or put tokens/passwords in command-line arguments or shell history.
The separate `inventories/vault.yml.example` is reference material, not an
automatically loaded secret store.

The controller needs Python 3 and Ansible Core 2.16+; CA source validation also
uses OpenSSL. `requirements.yml` has no Galaxy dependencies. Target package,
time and storage requirements remain real checks; downloading binaries does
not install every OS dependency.

Keep existing variable names: shared/DNS/Caddy/Forgejo use **`micolab_`** and
canonical CA/TLS use **`microlab_`**. For example,
`micolab_technitium_api_token` feeds `microlab_technitium_api_token`, and
`micolab_technitium_tls_cert_password` feeds the TLS PFX password. Do not rename
all keys by search/replace. See role defaults for each alias.

Stage reviewed, checksum-pinned controller artifacts:

```bash
./microlab artifacts --inventory inventories/site/hosts.yml
```

The wrapper uses the checkout's `artifacts/` cache and delegates to
`scripts/microlab_artifacts.py`. That module writes only its marked
`zz_microlab_artifacts.yml` group-var file, preserving `main.yml`, Vault and
existing downloads. Unsupported custom versions require explicit pinned staged
bytes; URLs are not guessed. The wrapper forwards `--offline` (existing files
only) and read-only `--check` (no downloads or metadata writes) to the module,
preserving its JSON result and exit status.

Generated step archive controller paths are transferred by the CA role. The
legacy target-local `file:///srv/microlab/artifacts` interface still refers to
infra's filesystem. No download result proves a running service or valid CA.

## Deliberate bootstrap handoffs

Choose the stage explicitly for a repeatable handoff. These are explicit
real-host operations:

```bash
./microlab deploy --inventory inventories/site/hosts.yml --stage bootstrap
# After storing protected first-enrollment credentials:
./microlab deploy --inventory inventories/site/hosts.yml --stage services
```

It prompts for Vault/become credentials as needed; `--no-become-prompt` is for
already configured passwordless sudo or protected Ansible become credentials.
It limits execution to localhost and the single infra alias. Setup/status do
not deploy. Missing offline CA inputs stop locally before a playbook runs.

1. Create the CA. After `setup` and `artifacts`, run:

   ```bash
   ./microlab ca-init --inventory inventories/site/hosts.yml
   ```

   It downloads the pinned `step` CLI for this machine and creates a 10-year
   root, a 5-year intermediate and the Technitium JWK provisioner. It checks
   them with the same OpenSSL tests deploy uses, then writes
   `group_vars/microlab_management/ca.yml` and the Vault-encrypted
   `ca-vault.yml`. Material goes in `inventories/site/ca/` (git-ignored); it
   refuses to run if that directory or any CA setting already exists.

   Then move `inventories/site/ca/offline-root/` (the root private key and its
   encrypted password) off this machine, onto a USB stick or into a password
   manager. Deploy never needs it; you only need it to issue a new
   intermediate. Keep a backup of the rest of `inventories/site/ca/`: deploy
   reads those files.

   The root key is briefly created on this workstation, which is fine for a
   lab. For a stricter split, run the
   [manual ceremony](ca-recovery.md#one-time-offline-initialization) on an
   offline machine and set these variables yourself (secrets in a Vault file):

   | Variable | Value |
   | --- | --- |
   | `microlab_step_ca_root_cert_src` | Absolute controller path to the public root certificate |
   | `microlab_step_ca_intermediate_cert_src` | Absolute controller path to the intermediate certificate |
   | `microlab_step_ca_intermediate_key_src` | Absolute controller path to the **encrypted** intermediate key |
   | `microlab_step_ca_root_fingerprint_sha256` | Root certificate SHA-256 fingerprint |
   | `microlab_step_ca_intermediate_key_password` | Vault: intermediate key password |
   | `microlab_step_ca_technitium_jwk_key` | Public JWK of the Technitium provisioner |
   | `microlab_step_ca_technitium_jwk_encrypted_key` | Vault: encrypted provisioner JWK |
   | `microlab_step_ca_initial_deploy: true` | **First CA deployment only** |

   `deploy` stops locally, before contacting infra, while any of the first
   seven is missing. It cannot see the target, so the last one is yours to set:
   without it a first bootstrap stops at the CA phase after DNS is installed.
   Set it only for genuinely new CA state; interrupted state needs the
   recovery procedure.
2. Bootstrap DNS, CA and initial Caddy with the staged entry point. A deliberate
   successful handoff must explain which inputs come next. Missing TLS tokens
   must not be simulated by supplying dummy values or treating an assertion
   failure as success.
3. After successful CA initialization, remove the initial-deploy flag. Create
   a persistent Technitium Settings View/Modify API token through its loopback
   console/API. An SSH tunnel to infra loopback `5380` can expose it locally;
   this does not authorize opening the backend to players. Store the token in
   protected inputs for unattended renewal.
4. On infra, mint the short-lived single-use enrollment token with
   `/usr/local/sbin/step-ca-technitium-token dns.microlab.hnh` using the JWK
   provisioner password. If `ca-init` created the CA, show that password on
   the workstation with `ansible-vault view
   inventories/site/ca/technitium-provisioner-password.vault.yml`. Store the
   token privately and resume the TLS/install stage
   promptly. Clear it after enrollment; keep the persistent API/PFX secrets.
   The token's lifetime is ten minutes; expiry requires a fresh token.
5. Finish Forgejo/final Caddy and installation checks. Prepare the initialized
   disposable Forgejo acceptance repository, write credentials, registered SSH
   key and pinned host keys only when requesting Git acceptance. The
   [advanced reference](setup.md) explains these manual handoffs in detail.

Resume with `./microlab deploy --stage services --inventory ...`, preserving
deployed CA state and durable secrets. Bootstrap ends successfully at
`credential-checkpoint`; installation ends at `local-ready` only after local
checks. Do not run the legacy full site play just to discover which protected
assertion fails next. A real gate failure still needs correction;
rerunning is not evidence that its earlier side effects were rolled back.

After successful enrollment, clear the consumed one-use token and continue
using `--stage services`; renewal uses the existing certificate and persistent
API/PFX credentials. Without `--stage`, deploy selects bootstrap when the API
credential is missing, selects services when both credentials are supplied,
and stops locally for stage selection when only the API credential remains.
It never infers enrollment or installation from a local marker, and never
returns to bootstrap merely because the one-use token was cleared. Do not
retain a consumed token or supply a dummy token. `verify` selects its own
acceptance playbook independently.

## Verify installation, then request acceptance

`status` is a **local controller prerequisite report**. It never fetches remote
installation reports and always labels remote installation/acceptance
UNVERIFIED. It never opens encrypted vars files: it reports plain inputs
(CA file paths, artifact declarations) and lists values it could not see as
"not visible without Vault". `deploy` unlocks and checks those for real.

`verify` runs full acceptance, including external and Git checks. There is no
local-only verification mode on this command; local checks already run during
deploy. Request it once its real inputs are ready:

```bash
./microlab verify --inventory inventories/site/hosts.yml
```

No acceptance claim follows from a mock test, download, syntax check, a stale
report, or an override that permits missing probes.

External DNS, CA/admin HTTP, DoH/DoT denial tests may wait until you have real
vantages. They need not be extra physical machines, but must actually exercise
the intended routes and source policy. Missing probes remain pending. Git
acceptance writes and removes branches in an operator-provided disposable repo.
Reboot, actual renewal-window issuance with WAN disconnected and the CA running,
and isolated restore are separate operational acceptance work. See
[validation](validation.md), [renewal](certificate-renewal.md) and
[backup/restore](backup-restore.md).

## Handoff to the rCTF + microVM host

Prepare its OS using [the Debian installation guide](rctf-debian-install.md),
including the network reservation and KVM readiness checks, before this handoff.

Infra and workload share a player-accessible subnet, not a trust boundary.
Workload host `.72` uses infra `.73` for internal DNS as authorized by its
operator; this repo does not rewrite its resolver, routes, firewall or router.
Keep all four management records pointing to `.73`.

The fork's [Compose source](https://github.com/Caden64/rctf/blob/9bc7c10c63d873b76eea32b7de815c8dc547d709/compose.yml)
binds rCTF HTTP to `127.0.0.1:8080` on the workload host. An infra loopback
upstream cannot reach that service across hosts. Keep workload ingress on the
workload host and arrange its own hostname/edge deliberately; the existing
infra Caddy vhosts remain for CA, DNS and Git.

The fork's [agent configuration](https://github.com/Caden64/rctf/blob/9bc7c10c63d873b76eea32b7de815c8dc547d709/deploy/firecracker/agent.example.yaml)
uses `network.publicHost` and `network.httpDomain` for player endpoints.
Choose a separate workload namespace, with its base and instance wildcard A
records pointing to `.72`. Do not point instance wildcard records at infra or
replace the `hnh` authoritative zone. Manage explicit A/AAAA records in infra
only for names it owns (`micolab_dns_extra_records` supports those types);
subzone NS delegation/wildcard reconciliation needs separate reviewed support.
Do not let the fork and Technitium independently overwrite the same records.

The [controller configuration](https://github.com/Caden64/rctf/blob/9bc7c10c63d873b76eea32b7de815c8dc547d709/deploy/firecracker/controller.example.yaml)
requires matching host IDs/tokens and verified HTTPS trust when TLS is used.
Controller and agent can be services on the same workload host; they do not
imply additional physical hosts. Its sample private addresses and capacity
values are examples, not this site's inputs. The
[Traefik sample](https://github.com/Caden64/rctf/blob/9bc7c10c63d873b76eea32b7de815c8dc547d709/deploy/firecracker/host/traefik.yml)
terminates workload TLS on that host. Public-root trust distribution, issuance,
SAN coverage and renewal for workload certificates remain an explicit handoff;
this repo's restricted CA policy is not a promise to issue arbitrary workload
or wildcard certificates. No rCTF deployment or fork modification is performed
by this onboarding.
