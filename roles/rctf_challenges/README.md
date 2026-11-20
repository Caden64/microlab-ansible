# rctf_challenges

Experimental implementation; no live deployment has been validated. See
[validation evidence and limits](../../docs/validation.md) and
[the challenges runbook](../../docs/challenges.md).

Stages CTF challenge workloads onto the dedicated rCTF Firecracker host (the
single `microlab_challenge` inventory host). The role never runs on the
management host, never installs or configures the rCTF application itself, and
never rewrites operator-owned files on the rCTF host.

Three stages, selected by `./microlab challenges deploy [--stage ...]`:

| Stage | What it does |
| --- | --- |
| `images` | Copies the digest-pinned guest images into the agent's `imagesDir`, re-verifies digests on the host, and asserts the agent's image-trust rules (root ownership, `0644`, regular files). |
| `edge` | Installs the pinned Traefik (loopback only), points its file provider at the agent's dynamic directory, renders one Caddy include for the workload namespace, and verifies the full public chain Caddy → Traefik with a fail-closed probe. The operator adds one `import` line to the rctf-edge Caddyfile; this role never edits that file. |
| `register` | Exchanges the host's admin team token for a session at the local API and upserts each challenge record via `PUT /api/v2/admin/challs/:id`, injecting flags from the vault. Reads back the admin challenge list and asserts every record's image before reporting success. |

## Inputs

Definitions come from this repository's `challenges/` directory, validated and
digest-pinned by [scripts/microlab_challenges.py](../../scripts/microlab_challenges.py).
The localhost play of `playbooks/challenges.yml` runs that check and passes
the result to this role as `micolab_challenges_definitions` and
`micolab_challenges_image_files`. Challenge flags are never part of those
inputs.

Required variables (private challenge-host inventory):

| Variable | Required | Meaning |
| --- | --- | --- |
| `micolab_rctf_challenges_flags` | register stage, vault | Mapping of challenge id to event flag. Nothing is registered without a flag for every definition. |
| `micolab_rctf_traefik_version` / `micolab_rctf_traefik_artifact_src` / `micolab_rctf_traefik_checksums` / `micolab_rctf_traefik_binary_sha256` | edge stage | Published by `./microlab challenges artifacts` into `group_vars/microlab_challenge/zz_microlab_challenges_artifacts.yml` (marked, generated file). |
| `micolab_rctf_expected_architecture` | edge stage, default `amd64` | Challenge host architecture; only the pinned linux_amd64 Traefik build exists. |

Shared defaults (see `defaults/main.yml` for the full list): the workload DNS
namespace `micolab_rctf_challenges_http_domain` (default
`fc.rctf.microlab.hnh`, asserted equal to the agent's `network.httpDomain`),
host paths matching the pinned rCTF installation, the loopback Traefik bind
(`127.0.0.1:8180`), and the Caddy include location
(`/etc/rctf-edge/challenges/challenges.include`).

## Fail-closed behaviour

- Missing agent configuration, unhealthy rCTF services, a missing admin token,
  an unimported Caddy include, digest drift, or a missing vault flag stop the
  run with instructions; no partial state is papered over.
- Registration is idempotent (the API upserts by id); re-running after a fix is
  safe. Images are re-verified on every deploy.
- The register stage proves the records exist and reference the pinned images.
  It does **not** prove that a player can launch an instance and reach an
  endpoint: those acceptance probes are documented in
  [docs/challenges.md](../../docs/challenges.md) and must be run before the
  event.

## TLS status

Workload endpoints are plain HTTP through the existing rctf-edge Caddy. A
wildcard certificate for the namespace (`*.fc.rctf.microlab.hnh`) is a
designed but **not implemented** extension; see docs/challenges.md for the
step-ca policy hooks that exist today.
