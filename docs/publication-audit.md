# Publication hygiene audit

Local review on 2026-11-10, limited to secret hygiene for the initial GitHub
publication. This is a snapshot of a shared checkout; repeat the review after
other edits finish and before adding files.

## Method and scope

- Enumerated publication candidates with
  `git ls-files --others --exclude-standard`, and checked the tracked-file list
  with `git ls-files` (empty at review time). Final enumeration contained 132
  candidates: 131 regular text files and one internal symlink.
- Read candidate regular files locally using a Python standard-library scanner
  for private-key headers, Ansible Vault ciphertext, common provider-token
  formats, credential-bearing URLs, credential assignments, IPv4 addresses,
  local home paths, and long encoded-looking literals. Reviewed match context
  with literal values withheld. No external uploads or host connections.
- Inspected inventory/example configuration, secret defaults and templates,
  and synthetic test credential/CA-generation context. The
  `playbooks/group_vars` symlink resolves inside the checkout to shared source.
- Enumerated ignored files separately. The observed ignored files were Python
  bytecode; their contents were not scanned. `.ansible/` contained no files.
  Gitleaks, TruffleHog, and detect-secrets were unavailable locally; this was a
  targeted local pattern/context review, not a dedicated scanner certification.

## Exclusions and checks

`.gitignore` now excludes local inventories outside `inventories/example/`,
root inventory/hosts files, local host/group variables except the published
`group_vars/all.yml`, vaults and password files, dotenv state, root operator
keys, local credential directories, staged artifacts, backups/quarantine,
virtual environments, bytecode, and common verification reports/logs.

The sanitized example inventory and `inventories/vault.yml.example` remain
visible. Role sources, `renewal.env.j2`, and synthetic test sources/fixtures
remain visible. Archive exclusions target local storage and root downloads;
they do not blanket-hide nested source archives or fixture keys.

Verified with `git check-ignore --no-index`: all 35 representative private or
generated paths were excluded, and all 19 representative example/source/fixture
paths remained visible. Hypothetical checks created no files. Also checked
actual candidate and ignored-file lists after the change, and confirmed all
94 existing role source files and 14 test source files remained unignored.

## Findings

No live credential was identified within the scanned candidate-file scope.
No private-key block, recognized provider token, credential-bearing URL, or
Ansible Vault ciphertext was detected there. Credential matches were empty
operator inputs, template/runtime references, replacement placeholders,
documented upstream bootstrap behavior, or synthetic test strings. CA tests
generate disposable material in temporary directories; those strings and
generators are source, not deployed credentials. Example inventory uses
replacement host/user values and illustrative networks. Home-directory matches
describe the service account's runtime paths, not an operator environment.
No actual local inventory, backup archive, or generated verification report
was identified among the reviewed publication candidates.

## Operator review before `git add`

Review the fresh candidate list and intended diff, especially edits to the
publishable example inventory and `group_vars/all.yml`. Confirm all addresses,
domains, users, paths, fingerprints, checksums, and literal credentials are
intentional public examples. New secret filenames, nested key files, arbitrary
logs, encodings, and unknown token formats can evade these patterns. Keep real
inventory, CA/private keys, vault password files, backups, and reports outside
the publishable source tree. Confirm MIT attribution in `LICENSE` and rights
to any included third-party material.

Ignore rules do not remove already tracked secrets, inspect Git history, or
prove absence of secrets. Ignored contents, external paths, and history were
not content-audited. No files were staged, committed, pushed, or published;
no secrets were deleted or overwritten. This pass did not rerun the reported
unit/syntax/lint checks or validate deployment, reboot, offline renewal, or live
restore. See [validation.md](validation.md) for validation scope.
