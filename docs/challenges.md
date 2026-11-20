# CTF challenge deployment

Deploy the event's Firecracker microVM challenges onto the rCTF host
(`microlab_challenge`, the NUC) through this repository's definitions and the
`./microlab challenges` commands. This is experimental tooling in the same
status as the rest of the repository: **no live challenge deployment has been
validated**. Everything here fails closed; nothing below is acceptance.

The platform side (rCTF, the Firecracker controller and agent, the edge) is
installed by the pinned rCTF host procedure, not by this repository — see
[rCTF on the NUC](rctf-deployment.md) first. This page only covers challenge
images, the workload edge and challenge records.

## The event challenges

Two web challenges are SPLIT into staged records: each stage is its own
scoreboard entry with its own flag and points, sharing one guest image.
The two records of a pair look identical to players; only the flag's
location differs, chosen by the per-record `CHALLENGE` environment value.
Each record spawns its own instance per team (the platform keys instances
per record), so a team working both stages of one site runs two copies of
it. The recon stage is the enumeration entry; the main stage is the
exploit entry.

| Definition | Category | Lab in the rCTF fork (`rctf-firecracker`) | Image |
| --- | --- | --- | --- |
| `challenges/xweb-recon/` | web | `deploy/firecracker/labs/xweb` (branch `challenge/xweb-portal`) | `xweb-vuln` (shared) |
| `challenges/xweb-portal/` | web | same lab | `xweb-vuln` (shared) |
| `challenges/m364-recon/` | web | `deploy/firecracker/labs/php2shell` (branch `challenge/php2shell-m365`) | `php2shell-vuln` (shared) |
| `challenges/m364-credit/` | web | same lab | `php2shell-vuln` (shared) |
| `challenges/sshhole-yocto/` | pwn | `deploy/firecracker/labs/sshole-yocto` (branch `challenge/sshole-yocto`) | `sshole-yocto-musl` |

Staged records sharing an image pin the SAME manifest digests; keep their
manifests in sync when a lab rebuild is re-pinned.

Each definition directory contains:

| File | Purpose |
| --- | --- |
| `challenge.yaml` | The rCTF admin challenge payload minus the flag: name, category, description, points, and the `instancerConfig` (image, resources, readiness, expose). `id` is also the challenge record id and `challengeIntegrationId`. |
| `manifest.yml` | The pinned build output: image name plus `sha256`/`size` for `vmlinux` and `rootfs.ext4`. Filled by `./microlab challenges manifest`, never by hand. |

**Flags are never stored in this repository.** The register stage injects each
flag from the vault mapping `micolab_rctf_challenges_flags` keyed by challenge
id. Descriptions and points are yours to edit; `challengeIntegrationId` never
changes after launch.

## Workflow

### 1. Build the lab images

Build each lab in the fork and record the green run in its `RESULTS.md`
(follow `deploy/firecracker/labs/README.md` in that repository; the labs are
unprivileged and run their own throwaway nested-KVM verification VM):

```bash
cd <rctf-firecracker worktree>/deploy/firecracker/labs/<name>
./build.sh            # the M364/php2shell lab builds with ./build-oci.sh
./run.sh
```

The built images land in the lab's cache directory under `$XDG_CACHE_HOME`
(see each lab's README for the exact path).

### 2. Pin the manifests

```bash
./microlab challenges manifest \
  --images-dir ~/.cache/rctf-sshole-yocto/images \
  --images-dir ~/.cache/rctf-xweb/images \
  --images-dir ~/.cache/rctf-p2s-lab/images
```

`--images-dir` is repeatable; each directory must contain
`<image>/{vmlinux,rootfs.ext4}`. Unfilled `REPLACE_` markers are filled in
place. A rebuilt image whose digest changed is a reviewed change: re-pin with
`--allow-update` after checking the new build's `RESULTS.md`. A deploy never
runs with unfilled markers or digest drift.

### 3. Stage the edge artifact

```bash
./microlab challenges artifacts
```

Downloads the pinned Traefik 3.7.15 archive (same reviewed sha256 as the
fork's edge pinning), verifies it, and publishes
`group_vars/microlab_challenge/zz_microlab_challenges_artifacts.yml` in the
private inventory. `--offline` and `--check` behave like the infra artifacts
command. Only the linux_amd64 build is pinned; the NUC is amd64.

### 4. Store the event flags

Flags are generated and vault-encrypted in one step:

```bash
./microlab challenges flags --inventory inventories/site/hosts.yml
```

It reads the challenge ids from `challenges/`, generates a random `rctf{...}`
flag for every definition that does not have one, encrypts them into
`inventories/site/group_vars/microlab_challenge/challenges-vault.yml`, and
prints each flag exactly once for your answer key. Existing stored flags are
never replaced; change one deliberately with `ansible-vault edit`. Re-running
is safe (it only fills what is missing). The command needs the Vault password
(from your terminal, or `ANSIBLE_VAULT_PASSWORD_FILE` for a non-interactive
run); the flags never appear in this repository.

To choose your own flag strings instead, create the same file by hand:

```bash
mkdir -p inventories/site/group_vars/microlab_challenge
ansible-vault create inventories/site/group_vars/microlab_challenge/challenges-vault.yml
```

```yaml
micolab_rctf_challenges_flags:
  fc-sshhole-yocto: <event flag>
  fc-xweb-recon: <event flag>
  fc-xweb: <event flag>
  fc-m364-recon: <event flag>
  fc-m364-credit: <event flag>
```

### 5. DNS namespace for web endpoints

Web endpoints are published as `<hostPrefix>-<instance
id>.fc.rctf.microlab.hnh`. Add the wildcard record through the interface the
DNS role already owns, in the private inventory:

```yaml
micolab_dns_extra_records:
  - { name: "*.fc.rctf.microlab.hnh", type: A, value: <rctf host address>, ttl: 60 }
```

Then converge DNS with `./microlab deploy --stage services`. The challenge
deployment verifies the record afterwards and fails closed if it does not
resolve to the rCTF host. Accepting an unverified namespace is possible only
by setting `micolab_rctf_challenges_dns_accept_unverified: true` in the
private inventory; it is never the default.

### 6. One Caddy import line on the NUC

The workload namespace is proxied by the existing `rctf-edge` Caddy. This
repository never rewrites that operator-owned file; add exactly one import
line to `/etc/rctf-edge/Caddyfile` on the NUC:

```caddyfile
import /etc/rctf-edge/challenges/challenges.include
```

The deployment creates the include file, verifies the import exists, reloads
Caddy, and probes the chain. Without the import line the edge stage fails
closed with this instruction.

### 7. Deploy

The orchestrator runs the whole pipeline in order, skipping completed work:

```bash
./scripts/deploy_challenges.sh
```

Stages: `preflight` (tools, images, definitions, host reachability, NUC
services — read-only) → `flags` (generate + vault-encrypt missing flags,
local) → `artifacts` (stage the pinned Traefik and publish its generated
vars into the site inventory, local) → `dns` (verify the wildcard against
the authoritative server; only a confirmed NXDOMAIN triggers the infra
convergence — note that `./microlab deploy --stage services` converges CA,
encrypted DNS, Caddy and Forgejo as well as the record) → `caddy` (render
the include, validate a candidate Caddyfile, then install + reload with a
rollback path, on the NUC with sudo) → `deploy` (the launcher's full stage
set) → `accept` (DNS + edge-chain probe, a real instance launch per
challenge through the admin API, controller-side endpoint probes with
per-challenge content markers and the SSH banner, and verified teardown).
Run a single stage with `--stage <name>`; `--stage preflight` is read-only
and safe anywhere.

Credentials: the script never stores a password. The Vault password is
consumed by the underlying `./microlab` prompts (terminal, or
`ANSIBLE_VAULT_PASSWORD_FILE`). sudo is INTERACTIVE: the two hosts have
different users and different sudo passwords, users are always taken from
the site inventory, and each privileged phase batches into one prompt
(caddy, launch, cleanup on the rCTF host; `--ask-become-pass` on the infra
host). For a fully non-interactive run, provide both protected per-host
password files (mode 0600, never committed):

```bash
export MICROLAB_NUC_PASS_FILE=/path/to/nuc-sudo-pass   # 10.72.78.72
export MICROLAB_PI_PASS_FILE=/path/to/pi-sudo-pass     # 10.72.78.73
```

Equivalently, the manual per-step flow:

| Stage | Effect | Verified by |
| --- | --- | --- |
| `images` | Copies `vmlinux`/`rootfs.ext4` into the agent's `imagesDir` | sha256 re-verified on the host; ownership and mode asserted against the agent's image-trust rules |
| `edge` | Installs pinned Traefik on `127.0.0.1:8180` (file provider on the agent's dynamic directory), renders the Caddy include | archive and binary digests verified on the host; loopback probe; public-edge probe through Caddy |
| `register` | Upserts each challenge record via the local rCTF admin API with the vault flag | per-record response kind asserted; admin-list readback asserts id, image and integration id |

`--stage` selects one stage (`images`, `edge` or `register`) for a partial
re-run. Infra is contacted only to verify the DNS namespace. The register
stage is idempotent (the API upserts by id); a partial failure can be fixed
and re-run safely.

Challenges are registered **hidden** (`hidden: true` in `challenge.yaml`);
unhide them from the rCTF admin UI when the event opens.

## Acceptance before the event

A completed playbook is not acceptance. Before opening registration, with the
event's real network:

1. **Instance launch.** As a test team (register one or use the admin team),
   start each challenge from the rCTF UI and confirm the instance reaches
   `running`. A failing launch means the image, readiness probe or exposed
   port is wrong — fix the definition or the lab, not the host.
2. **Endpoint reachability.** From the **player subnet**, resolve and reach
   one web endpoint (`http://<hostPrefix>-<id>.fc.rctf.microlab.hnh`) and one
   raw TCP endpoint (`<nuc address>:<public port from the instance details>`,
   inside the configured `tcpPortRange`, 20000–20999). The NUC port guard
   blocks 7000/7001/8080 only; challenge ports must be reachable.
3. **Isolation and teardown.** Launch the same challenge from two test teams;
   confirm each endpoint reaches only its own guest and that deleting an
   instance removes tap, rules, Traefik file and run directory (the agent
   reports this; check its logs).
4. **Expiry.** Confirm the instance expires at `timeoutMilliseconds` and that
   extending works from the UI.

Record what actually ran and what did not, the same way the rest of this
repository does; missing probes stay pending, never passed.

## TLS status for the workload namespace

Workload endpoints are **plain HTTP** through the rctf-edge Caddy. A wildcard
certificate for `*.fc.rctf.microlab.hnh` is a designed but **not implemented**
extension. The step-ca hooks exist today: the CA policy renders from
`microlab_step_ca_allowed_dns_names` and `microlab_step_ca_allow_wildcard_names`
(`roles/step_ca/defaults/main.yml`), and a JWK provisioner can mint such a name
once it is allowed. Implementing it means: extending the policy, minting and
installing the key pair on the NUC, and terminating TLS either at Traefik on a
public port or at Caddy with a pass-through to Traefik's TLS entrypoint. Do
not claim it works until a real chain has been exercised end to end.

## Known limits

- Only the linux_amd64 Traefik build is pinned; a non-amd64 challenge host
  fails closed at `./microlab challenges artifacts`.
- `tcp-ssl` exposes would need Traefik TLS (see above); the definitions here
  use `tcp` and plain `http` only.
- The register stage touches only challenge records. Event settings
  (`startTime`, `endTime`, `registrationsEnabled`) are edited on the host
  per [rCTF on the NUC](rctf-deployment.md).
- The agent's image catalog is the `imagesDir` on the NUC; staging an image
  that no challenge references is harmless, but a challenge referencing an
  unstaged image fails at instance launch, not at deploy. The readback check
  catches name drift only.
