# rCTF on the NUC

The MicroLab site runs rCTF at **https://rctf.microlab.hnh/** on the NUC
(`10.72.78.72`). The Pi (`10.72.78.73`) answers DNS for the name and
issues the certificate. The NUC belongs only in `microlab_challenge`.
Use the [Debian installation guide](rctf-debian-install.md) for a bare NUC.

The deployed application was built from the
[rCTF fork at `9bc7c10`](https://github.com/Caden64/rctf/tree/9bc7c10c63d873b76eea32b7de815c8dc547d709).
On November 19, 2026, the HTTPS health endpoint, admin login, PostgreSQL,
Redis, and authenticated controller access from the rCTF container passed.
The Firecracker controller reported the NUC healthy. The image catalog was
empty, so a guest launch and player challenge endpoint remain unverified.

## Connect and check the running services

Players need to resolve `rctf.microlab.hnh` with Technitium on the Pi and
trust the MicroLab public root. The HTTPS site and certificate use that
hostname. For a quick check before enrolling browser trust, run this on the
**laptop** from the infra checkout with the private site inventory:

```bash
curl --fail --cacert inventories/site/ca/root_ca.crt \
  --resolve rctf.microlab.hnh:443:10.72.78.72 \
  https://rctf.microlab.hnh/api/healthz
```

Expect `ok`. On the **NUC**, check DNS and the system services:

```bash
dig @10.72.78.73 rctf.microlab.hnh A +short
systemctl is-active docker rctf-edge rctf-port-guard \
  rctf-firecracker-agent rctf-firecracker-controller
curl --fail http://127.0.0.1:8080/api/healthz
```

Expect `10.72.78.72`, five `active` results, and `ok`. Enter a root shell
on the NUC for Docker and configuration access:

```bash
sudo -i
cd /home/rctf-data/application
docker compose --project-name microlab-rctf ps
docker compose --project-name microlab-rctf logs --tail=40 rctf
docker compose --project-name microlab-rctf exec -T rctf rctf user list-admins
exit
```

PostgreSQL and Redis should show as healthy. The displayed admin is
`microlab-admin` (`admin@microlab.hnh`).

## Admin login and event settings

In a private terminal on the **NUC**, retrieve the admin team token with
`sudo cat /home/rctf-data/application/admin-team-token`. Paste the token into
the team-token login at the HTTPS site. Keep the token in your password
manager. Anyone with the token can sign in as that account.

Public registration is closed. The initial event timestamps are placeholders.
Before inviting players, set real `startTime` and `endTime` values in Unix
milliseconds and review divisions and `registrationsEnabled` in
`/home/rctf-data/application/rctf.d/00-microlab.json`. Keep the existing
`tokenKey`. Edit as root and retain the file permissions. Apply a config
change from the application directory with:

```bash
docker compose --project-name microlab-rctf up -d --no-build --no-deps --force-recreate rctf
```

Run the HTTPS health check again after recreation.

## Installed layout and rebuild notes

| Component | Installed location or configuration |
| --- | --- |
| rCTF source, Compose and config | `/home/rctf-data/application` with `.microlab-source` recording the revision |
| Docker engine | `/etc/docker/daemon.json`, data root `/home/rctf-data/docker` |
| App storage | `.data/postgres`, `.data/redis`, and `.data/uploads` under the application directory |
| App credentials | Application `.env`, `rctf.d/00-microlab.json`, and root-only `admin-team-token` |
| NUC HTTPS and port guard | `/etc/rctf-edge`, with `rctf-edge.service` and `rctf-port-guard.service` |
| Firecracker sources and config | `/opt/rctf-firecracker` and `/etc/rctf-firecracker` |
| Agent disk and jail state | `/var/lib/rctf-firecracker`, bind-mounted from `/home/rctf-data/firecracker` |
| Controller database | `/var/lib/rctf-firecracker-controller/controller.sqlite` |

For a rebuild with existing data, restore the protected configuration and
state first. Use the same pinned revision, tokens, image versions and project
name. Preserve the database bind mount paths.

1. On Debian, install `docker.io`, `docker-cli`, and `docker-compose`.
   Put Docker's data root on the large SSD partition before starting Docker.
   This NUC has a small separate `/var`. Use the fork's Compose file with
   `rctf` built from the pinned source under a local image name such as
   `microlab/rctf:<commit>`. The dependency stage at this revision must copy
   both `apps/firecracker-instancer/package.json` and
   `packages/firecracker/package.json` into their matching paths before the
   frozen Bun install. With the deployed `postgres:18.0` image, the host
   directory mounted at `/var/lib/postgresql` needs to be accessible to
   Postgres UID/GID 999. The rCTF process reads mounted config as UID/GID
   1001. Keep the Compose app port on `127.0.0.1:8080` and keep the database
   ports on the Docker network.
2. Add A record `rctf.microlab.hnh → 10.72.78.72` in Technitium's `hnh`
   zone. In the Pi's private inventory, set
   `micolab_caddy_acme_client_cidrs: ["10.72.78.72/32"]`.
   This requires the updated Caddy role. Its CA frontend forwards the
   public CA hostname as the upstream Host and grants this source only
   `/acme/acme/*`. The NUC's Caddy 2.11.9 uses
   `https://ca.microlab.hnh/acme/acme/directory`, the public MicroLab root,
   and HTTP-01. It proxies the site to the loopback app port. The Pi must
   resolve the rCTF name and reach the NUC's port 80 for renewal.
3. For Firecracker, follow the [pinned host setup guide](https://github.com/Caden64/rctf/blob/9bc7c10c63d873b76eea32b7de815c8dc547d709/deploy/firecracker/host/README.md).
   The deployed versions are Bun 1.4.4 and Firecracker/jailer 1.17.0.
   With the SSD mount active, point the jailer at
   `/var/lib/rctf-firecracker/jailer`. Keep the agent on `127.0.0.1:7001`.
   The controller listens on port 7000 at the gateway of `rctf_network`
   (currently `172.19.0.1`). Discover it using
   `docker network inspect rctf_network` after a rebuild. Use a matching
   `FIRECRACKER_INSTANCER_API_URL` and controller auth token in the app
   `.env`. Keep the controller's admin token and the agent credentials
   separate. The NUC port guard blocks direct LAN access to ports 7000,
   7001 and 8080.

Back up the app database and uploads consistently, the protected configuration
and tokens, and the Firecracker controller and agent state. Keep a copy away
from the NUC. The Pi's backup covers the infra host and its private CA.

## Before opening microVM challenges

Stage approved guest images and add at least one challenge that references a
staged image. The current host ID is `nuc`, the guest subnet pool is
`10.200.72.0/24`, and raw player endpoints use the configured TCP port range
`20000–20999`. Review these settings against the event's traffic and capacity.

Challenge images, records and the workload edge are now deployed through this
repository instead of by hand: see
[CTF challenge deployment](challenges.md). It stages digest-pinned images into
the agent's catalog, installs the pinned loopback Traefik behind the
`rctf-edge` Caddy for the `fc.rctf.microlab.hnh` namespace, and registers the
challenge records (hidden) with flags from the vault. The wildcard DNS record
is added through `micolab_dns_extra_records` and the playbook verifies it.

For HTTP or TLS challenge endpoints, the TLS namespace certificate remains
**not implemented**; the current deployment serves the workload namespace
over plain HTTP through Caddy, and the step-ca policy hooks for a wildcard
certificate are documented in [challenges.md](challenges.md). Verify one
benign instance launch, player reachability, and cleanup before opening
registration or loading the event's challenges.
