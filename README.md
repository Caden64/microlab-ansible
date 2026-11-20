# MicroLab Ansible

Set up one Debian 12/13 **infra host** running Technitium DNS, step-ca, Caddy
and Forgejo together. A **second host** runs
[Caden64/rctf](https://github.com/Caden64/rctf) and its microVM workloads.
There are exactly two installation hosts. This repository configures infra;
it does not install rCTF or configure the router/workload host.

For this site, infra is the Raspberry Pi at **10.72.78.73** and the workload
host is **10.72.78.72**, on the player-accessible **10.72.78.0/24**.
These are site inputs, not universal defaults. A stable DHCP reservation is
sufficient. The actual admin workstation `/32` or protected VPN CIDR is still
required: do not grant admin access to the entire player subnet or use the
infra address as the operator's identity.

Installing the second host's OS? Follow [Debian installation for the rCTF host](docs/rctf-debian-install.md)
for USB preparation, installer choices, the `.72` reservation, SSH and KVM checks.

Start with [fresh-clone onboarding](docs/fresh-clone.md). The shared executable
interface is:

```bash
./microlab setup
./microlab artifacts
./microlab deploy
./microlab verify
./microlab status
./microlab challenges manifest   # pin lab image digests, no host contact
./microlab challenges artifacts  # stage the pinned edge binary, no host contact
./microlab challenges flags      # generate + vault-encrypt event flags (local)
./microlab challenges deploy     # stage images/edge/records on the rCTF host
```

Read each command's `--help` for its implemented options. Setup and artifact
preparation are controller work; deploy and verify are deliberate operations
against inventory targets. The `challenges` commands deploy CTF workloads to
the separate rCTF host — see [the challenges runbook](docs/challenges.md).
Reuse your already filled private inventory. Never
copy example values over it to start again.

This remains experimental; no live infra deployment has been validated.
Installation readiness and complete acceptance are separate. Missing tokens,
offline CA material, or external probe evidence cannot be called passed.
[Validation status](docs/validation.md) records local evidence and remaining gaps.

## Names, ports and trust

The authoritative zone stays **hnh** and the service domain **microlab.hnh**.
`ns1`, `ca`, `dns` and `git.microlab.hnh` all point to the infra address `.73`.
All existing loopback backends stay on that same infra host.

| Port on infra | Purpose |
| --- | --- |
| 22/tcp | Admin SSH and Forgejo Git over system OpenSSH |
| 53/udp,tcp | Technitium DNS |
| 80,443/tcp | Caddy; route ACLs further restrict CA and DNS administration |
| 853/tcp | Native Technitium DoT |
| 3000,4443,2019/tcp | Loopback Forgejo HTTP, step-ca, Caddy admin |
| 5380,8053/tcp | Technitium admin and HTTP DoH backends behind Caddy |

Client access to the subnet does not grant CA/DNS admin permission. A specific
admin `/32` may overlap the client `/24`; separate VLANs are not an installation
requirement. Infra self-traffic must still support CA HTTP01 and local Git
checks. Missing real external denial vantages remain pending acceptance.

`./microlab ca-init` creates the CA (root, intermediate and Technitium
provisioner) and adds it to inventory; move the root key it creates off the
workstation afterwards. Nothing distributes trust to arbitrary clients or
invents API tokens. Renewal with WAN disconnected still needs the local issuing CA running.
A stopped CA cannot renew certificates.

## References

- [rCTF on the NUC](docs/rctf-deployment.md) covers the deployed application, admin login, storage layout and Firecracker handoff.
- [CTF challenge deployment](docs/challenges.md): building the labs, pinning manifests, staging the edge and registering challenges.
- [Advanced inputs and legacy site workflow](docs/setup.md), preserving the
  detailed manual reference; `playbooks/site.yml` remains the compatibility entry point.
- [DNS and firewall](docs/dns.md).
- [CA recovery](docs/ca-recovery.md) and [certificate renewal](docs/certificate-renewal.md).
- [Backup and isolated restore](docs/backup-restore.md).
- Role interfaces: [step-ca](roles/step_ca/README.md),
  [Technitium TLS](roles/technitium_tls/README.md), [Caddy](roles/caddy/README.md),
  [Forgejo](roles/forgejo/README.md), [verify](roles/verify/README.md),
  [rctf challenges](roles/rctf_challenges/README.md).

Shared/DNS/Caddy/Forgejo variables currently use `micolab_`; CA/TLS use
`microlab_`, with documented aliases. Keep existing spellings. Deployment
preserves this layout; spelling changes are not inventory migration instructions.

[MIT](LICENSE). Third-party binaries retain their own licenses.
