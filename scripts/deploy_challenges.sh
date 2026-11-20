#!/bin/bash
# MicroLab CTF challenge deployment orchestrator.
#
# Runs the whole pipeline against the live two-host site, in order:
#   preflight -> flags -> artifacts -> dns -> caddy -> deploy -> accept
#
# Each stage skips work that is already done, so re-running after a partial
# failure is safe. Run one stage with --stage <name>; default is all.
#
# Credentials: this script never stores a password.
#   - The Ansible Vault password is consumed by the underlying ./microlab
#     commands: type it at their prompt (terminal) or export
#     ANSIBLE_VAULT_PASSWORD_FILE for a non-interactive run.
#   - The two hosts have DIFFERENT users and DIFFERENT sudo passwords. sudo
#     is interactive by design: each privileged phase batches into one
#     prompt (caddy, launch, cleanup on the rCTF host; --ask-become-pass on
#     the infra host). For a fully non-interactive run, provide BOTH
#     protected per-host password files (mode 0600):
#       MICROLAB_NUC_PASS_FILE   rCTF host (10.72.78.72) sudo password
#       MICROLAB_PI_PASS_FILE    infra host (10.72.78.73) sudo password
#     Users are always taken from the site inventory, never hardcoded.
#
# Usage:
#   ./scripts/deploy_challenges.sh                     # everything
#   ./scripts/deploy_challenges.sh --stage accept       # just the probes
#   ./scripts/deploy_challenges.sh --stage deploy --images-dir DIR ...
#
# Environment overrides:
#   MICROLAB_SITE_CHECKOUT    main site checkout (default below)
#   MICROLAB_IMAGES_DIRS      colon-separated lab image caches
#   MICROLAB_NUC_PASS_FILE    protected file with the rCTF sudo password
#   MICROLAB_PI_PASS_FILE     protected file with the infra sudo password
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SITE_CHECKOUT="${MICROLAB_SITE_CHECKOUT:-/home/caden64/projects/microlab/microlab-ansible}"
DEFAULT_IMAGES_DIRS="${HOME}/.cache/rctf-sshole-yocto/images:${HOME}/.cache/rctf-xweb/images:${HOME}/.cache/rctf-p2s-lab/images"
IMAGES_DIRS="${MICROLAB_IMAGES_DIRS:-$DEFAULT_IMAGES_DIRS}"
STAGE="all"
EXTRA_IMAGES=()
SSH_KEY=""
NUC_PASS_FILE="${MICROLAB_NUC_PASS_FILE:-}"
PI_PASS_FILE="${MICROLAB_PI_PASS_FILE:-}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --stage) STAGE="${2:?--stage needs a value}"; shift 2 ;;
        --site-checkout) SITE_CHECKOUT="${2:?--site-checkout needs a value}"; shift 2 ;;
        --images-dir) EXTRA_IMAGES+=("${2:?--images-dir needs a value}"); shift 2 ;;
        -h | --help) sed -n '2,28p' "$0"; exit 0 ;;
        *) echo "deploy_challenges: unknown argument: $1" >&2; exit 2 ;;
    esac
done

SITE_INVENTORY="$SITE_CHECKOUT/inventories/site/hosts.yml"
[ "${#EXTRA_IMAGES[@]}" -gt 0 ] && IMAGES_DIRS="$(IFS=:; echo "${EXTRA_IMAGES[*]}")"
export SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-$(find "$HOME/.ssh/agent" -type s 2>/dev/null | head -1)}"

die() { echo "deploy_challenges: $*" >&2; exit 1; }
note() { echo "==> $*"; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1 (install it or run the failing stage manually)"; }

# Read the two hosts (and the infra identity file) out of the site inventory.
read_inventory_hosts() {
    [ -f "$SITE_INVENTORY" ] || die "site inventory not found: $SITE_INVENTORY"
    eval "$(python3 - "$SITE_INVENTORY" <<'PY'
import sys, yaml
class L(yaml.SafeLoader):
    pass
L.add_constructor('!vault', lambda loader, node: None)
with open(sys.argv[1]) as stream:
    inventory = yaml.load(stream, Loader=L)
def hosts(group):
    return ((inventory.get('all', {}).get('children', {}) or {}).get(group, {}) or {}).get('hosts', {}) or {}
management, challenge = hosts('microlab_management'), hosts('microlab_challenge')
assert len(management) == 1 and len(challenge) == 1, 'need exactly one infra and one rCTF host'
name, values = next(iter(challenge.items()))
print('NUC_ALIAS=%r' % name)
print('NUC_ADDRESS=%r' % values.get('ansible_host', ''))
print('NUC_USER=%r' % (values.get('ansible_user') or 'caden64'))
name, values = next(iter(management.items()))
print('PI_ADDRESS=%r' % values.get('ansible_host', ''))
print('PI_USER=%r' % (values.get('ansible_user') or 'hopkeeper'))
print('SSH_KEY=%r' % (values.get('ansible_ssh_private_key_file') or ''))
PY
)" || die "cannot parse the site inventory"
    : "${NUC_ADDRESS:?}" "${PI_ADDRESS:?}"
}

ssh_args() {
    [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ] && printf '%s\n' -i "$SSH_KEY" -o IdentitiesOnly=yes
    true
}
nuc_ssh() { ssh $(ssh_args) -o BatchMode=yes -o ConnectTimeout=8 "$NUC_USER@$NUC_ADDRESS" "$@"; }
pi_ssh() { ssh $(ssh_args) -o BatchMode=yes -o ConnectTimeout=8 "$PI_USER@$PI_ADDRESS" "$@"; }

check_pass_file() {
    [ -f "$1" ] || die "password file does not exist: $1"
    [ -O "$1" ] && [ "$(stat -c %a "$1")" = 600 ] \
        || die "password file must be your own file with mode 0600: $1"
}

# Run one root phase on the rCTF host. The command must reference a script
# FILE that was staged with nuc_put (never a stdin script, so sudo's password
# prompt can own the terminal). Interactive runs prompt once per phase;
# MICROLAB_NUC_PASS_FILE runs them without any prompt.
nuc_root() {
    if [ -n "$NUC_PASS_FILE" ]; then
        check_pass_file "$NUC_PASS_FILE"
        ( sleep 1; head -n1 "$NUC_PASS_FILE" ) \
            | ssh $(ssh_args) -o BatchMode=yes -o ConnectTimeout=8 \
                  "$NUC_USER@$NUC_ADDRESS" "sudo -S -k -p '' $*"
    elif [ -t 0 ]; then
        ssh $(ssh_args) -tt -o ConnectTimeout=8 "$NUC_USER@$NUC_ADDRESS" "sudo $*"
    else
        die "phase '$*' needs root on the rCTF host: run the script from a terminal to type the sudo password, or set MICROLAB_NUC_PASS_FILE"
    fi
}

nuc_put() {
    scp -q $(ssh_args) -o BatchMode=yes -o ConnectTimeout=8 "$1" \
        "$NUC_USER@$NUC_ADDRESS:/tmp/microlab-challenges-$(basename "$1")"
}

# Resolve one A record straight from a DNS server, validating the response:
# prints the first A address, NXDOMAIN, SERVFAIL, or ERROR:<rcode>.
dns_a() {
    # The resolver lives in scripts/dns_a.py: the parser once embedded here
    # was corrupted by the authoring transport (underscore placeholder
    # groups), which made it read nscount as ancount and report NXDOMAIN
    # for live records. It is executed (not just read) by the test suite.
    python3 "$HERE/scripts/dns_a.py" "$1" "$2"
}


stage_preflight() {
    note "preflight: tools"
    for tool in ansible-playbook ansible-vault python3 ssh scp curl; do need "$tool"; done
    note "preflight: checkouts and inventory"
    [ -d "$HERE/challenges" ] || die "challenges/ definitions missing in $HERE"
    [ -x "$SITE_CHECKOUT/microlab" ] || die "site checkout launcher missing: $SITE_CHECKOUT/microlab"
    read_inventory_hosts
    note "preflight: lab images ($IMAGES_DIRS)"
    for dir in ${IMAGES_DIRS//:/ }; do
        [ -d "$dir" ] || die "images directory missing: $dir (build the labs first; see docs/challenges.md)"
    done
    local argv=()
    for dir in ${IMAGES_DIRS//:/ }; do argv+=("--images-dir" "$dir"); done
    note "preflight: definitions validate against the local images"
    (cd "$HERE" && python3 scripts/microlab_challenges.py check \
        --inventory "$SITE_INVENTORY" --definitions challenges "${argv[@]}" \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["status"]=="ready", d.get("error","preflight failed");
print("     %d records: %s" % (len(d["definitions"]), ", ".join(x["id"] for x in d["definitions"])))') \
        || die "challenge preflight failed; no host was contacted"
    note "preflight: host reachability"
    nuc_ssh 'true' || die "cannot reach $NUC_USER@$NUC_ADDRESS (ssh agent?)"
    pi_ssh 'true' || die "cannot reach $PI_USER@$PI_ADDRESS (ssh agent?)"
    note "preflight: rCTF host services"
    local services
    services="$(nuc_ssh 'systemctl is-active docker rctf-edge rctf-port-guard rctf-firecracker-agent rctf-firecracker-controller')" \
        || die "systemctl failed on the rCTF host"
    [ "$(echo "$services" | sort -u)" = "active" ] || die "rCTF host services not all active: $(echo "$services" | tr '\n' ' ')"
    nuc_ssh 'curl -fsS --max-time 5 http://127.0.0.1:8080/api/healthz' >/dev/null \
        || die "the local rCTF API did not answer /api/healthz"
    echo "     all services active, healthz ok"
}

stage_flags() {
    note "flags: generate and vault-encrypt any missing event flag"
    (cd "$HERE" && ./microlab --inventory "$SITE_INVENTORY" challenges flags)
    note "flags: done (existing flags preserved; record the printed answer key)"
}

stage_artifacts() {
    note "artifacts: stage the pinned edge archive and publish the vars file"
    (cd "$HERE" && ./microlab --inventory "$SITE_INVENTORY" challenges artifacts) \
        || die "edge artifact staging failed (run ./microlab challenges artifacts online once)"
    [ -f "$SITE_CHECKOUT/inventories/site/group_vars/microlab_challenge/zz_microlab_challenges_artifacts.yml" ] \
        || die "the generated artifact vars file is missing from the site inventory; refusing to continue"
    echo "     pinned Traefik verified and published to the site inventory"
}

stage_dns() {
    note "dns: verify *.fc.rctf.microlab.hnh on the authoritative server"
    local answer
    answer="$(dns_a "$PI_ADDRESS" '*.fc.rctf.microlab.hnh')"
    if [ "$answer" = "$NUC_ADDRESS" ]; then
        echo "     wildcard already resolves to $NUC_ADDRESS"
        return 0
    fi
    [ "$answer" = "NXDOMAIN" ] \
        || die "the DNS lookup failed or the record answers wrongly (got: ${answer:-no answer}); not touching the infra host"
    note "dns: record missing; converging the infra host"
    echo "     (./microlab deploy --stage services converges CA, encrypted DNS,"
    echo "      Caddy and Forgejo as well as the record itself; it prompts for"
    echo "      the vault and become passwords)"
    if [ -n "$PI_PASS_FILE" ]; then
        check_pass_file "$PI_PASS_FILE"
        # The infra host has its own password: hand it to the site launcher's
        # ansible run through a protected become file, never a prompt.
        export ANSIBLE_BECOME_PASSWORD_FILE="$PI_PASS_FILE"
        BECOME_ARGS=(--no-become-prompt)
    else
        # Interactive run: let the site launcher prompt (--ask-become-pass)
        # for the infra host's sudo password.
        BECOME_ARGS=()
    fi
    (cd "$SITE_CHECKOUT" && ./microlab deploy "${BECOME_ARGS[@]}" --stage services) \
        || die "infra convergence failed; the wildcard record is not applied"
    answer="$(dns_a "$PI_ADDRESS" '*.fc.rctf.microlab.hnh')"
    [ "$answer" = "$NUC_ADDRESS" ] \
        || die "the wildcard record still does not resolve to $NUC_ADDRESS (got: ${answer:-no answer})"
    echo "     wildcard now resolves to $NUC_ADDRESS"
}

stage_caddy() {
    note "caddy: render the include, validate a candidate Caddyfile, then install with rollback (one sudo prompt)"
    local work
    work="$(mktemp -d)"
    cat >"$work/caddy-stage.sh" <<'REMOTE'
#!/bin/bash
# Runs as root on the rCTF host. One phase, one prompt.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "caddy: not running as root" >&2; exit 1; }
IMPORT="$1"
CADDYFILE=/etc/rctf-edge/Caddyfile
CANDIDATE=/etc/rctf-edge/Caddyfile.candidate
BACKUP=/etc/rctf-edge/Caddyfile.pre-challenges
INCLUDE_DIR=/etc/rctf-edge/challenges
INCLUDE="$INCLUDE_DIR/challenges.include"

install -d -m 0755 "$INCLUDE_DIR"
# Byte-identical to the rctf_challenges role template; the role render later
# is an idempotent overwrite of the same content.
printf 'http://*.fc.rctf.microlab.hnh {\n\treverse_proxy 127.0.0.1:8180\n}\n' > "$INCLUDE"
chmod 0644 "$INCLUDE"

CADDY="$(command -v caddy || true)"
if [ -z "$CADDY" ]; then
    CADDY="$(systemctl show rctf-edge -p ExecStart --value | sed -n 's/^path={\([^ }]*\).*$/\1/p' | head -1)"
fi
[ -n "$CADDY" ] && [ -x "$CADDY" ] || { echo "caddy: binary not found" >&2; exit 1; }

if grep -Eq '^[[:space:]]*import[[:space:]]+[^[:space:]#]*challenges[^[:space:]]*\.include' "$CADDYFILE"; then
    "$CADDY" validate --config "$CADDYFILE" --adapter caddyfile \
        || { echo "caddy: the active Caddyfile no longer validates" >&2; exit 1; }
    echo "caddy: import present and the active Caddyfile validates"
    exit 0
fi

cp "$CADDYFILE" "$CANDIDATE"
printf '%s\n' "$IMPORT" >> "$CANDIDATE"
if ! "$CADDY" validate --config "$CANDIDATE" --adapter caddyfile; then
    rm -f "$CANDIDATE"
    echo "caddy: the candidate Caddyfile did not validate; the live file is untouched" >&2
    exit 1
fi
cp "$CADDYFILE" "$BACKUP"
mv "$CANDIDATE" "$CADDYFILE"
chmod 0644 "$CADDYFILE"
if ! systemctl reload rctf-edge || ! systemctl is-active --quiet rctf-edge; then
    mv "$BACKUP" "$CADDYFILE"
    systemctl reload rctf-edge || true
    echo "caddy: reload failed; rolled back to the pre-challenges Caddyfile" >&2
    exit 1
fi
echo "caddy: import installed and Caddy reloaded (backup: $BACKUP)"
REMOTE
    nuc_put "$work/caddy-stage.sh"
    if ! nuc_root 'bash /tmp/microlab-challenges-caddy-stage.sh'; then
        nuc_ssh 'rm -f /tmp/microlab-challenges-caddy-stage.sh' || true
        rm -rf "$work"
        die "the caddy phase failed on the rCTF host (nothing installed unless reported above)"
    fi
    nuc_ssh 'rm -f /tmp/microlab-challenges-caddy-stage.sh'
    rm -rf "$work"
}

stage_deploy() {
    note "deploy: images + edge + register (launcher prompts for vault/become)"
    local argv=()
    for dir in ${IMAGES_DIRS//:/ }; do argv+=("--images-dir" "$dir"); done
    (cd "$HERE" && ./microlab --inventory "$SITE_INVENTORY" challenges deploy "${argv[@]}") \
        || die "challenges deploy failed; re-run this stage after fixing the reported issue"
}

challenge_ids() {
    (cd "$HERE" && python3 - <<'PY'
from pathlib import Path
import yaml
ids = []
for child in sorted(Path("challenges").iterdir()):
    path = child / "challenge.yaml"
    if path.is_file():
        ids.append(yaml.safe_load(path.read_text())["id"])
print(" ".join(ids))
PY
)
}

challenge_marker() {
    case "$1" in
        fc-xweb | fc-xweb-recon) printf '%s' 'XWEB-500' ;;
        fc-m364-credit | fc-m364-recon) printf '%s' 'M364' ;;
        *) printf '' ;;
    esac
}

stage_accept() {
    note "accept: DNS, edge chain, and a real launch per challenge from the controller side"
    local answer
    answer="$(dns_a "$PI_ADDRESS" '*.fc.rctf.microlab.hnh')"
    [ "$answer" = "$NUC_ADDRESS" ] || die "the workload DNS namespace does not resolve (run --stage dns first)"
    local edge_body
    edge_body="$(curl -s --max-time 8 --resolve "edge-probe.fc.rctf.microlab.hnh:80:$NUC_ADDRESS" \
        -H 'Host: edge-probe.fc.rctf.microlab.hnh' "http://edge-probe.fc.rctf.microlab.hnh/")" \
        || die "the public edge did not answer the namespace probe"
    grep -q '404 page not found' <<<"$edge_body" \
        || die "the namespace probe was not answered by Traefik (run --stage caddy/deploy first)"
    echo "     DNS + Caddy -> Traefik chain answers for the namespace"

    local ids
    ids="$(challenge_ids)"
    [ -n "$ids" ] || die "no challenge ids found in $HERE/challenges"

    note "accept: launching one instance per challenge as the admin team (one sudo prompt)"
    local work
    work="$(mktemp -d)"
    cat >"$work/accept-launch.py" <<'REMOTE'
import json, sys, time, urllib.error, urllib.request

API = "http://127.0.0.1:8080/api"
ids = sys.argv[1:]

def call(method, path, token=None, data=None, timeout=30):
    body = json.dumps(data).encode() if data is not None else None
    request = urllib.request.Request(API + path, method=method, data=body)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)

with open("/home/rctf-data/application/admin-team-token") as stream:
    team_token = stream.read().strip()
# JSON body, never a query string: the credential must not appear in any
# request URL or log line.
login = call("POST", "/v1/auth/login", data={"teamToken": team_token}, timeout=15)
assert login["kind"] == "goodLogin", "admin login was refused"
token = login["data"]["authToken"]

for challenge in ids:
    try:
        # Refuse to touch a pre-existing instance: the admin team's slot may
        # be someone's manual test in progress.
        try:
            call("GET", "/v2/admin/challs/%s/instance" % challenge, token)
            print(json.dumps({"id": challenge, "state": "PRE-EXISTING"}))
            continue
        except urllib.error.HTTPError:
            pass
        started = time.monotonic()
        created = call("PUT", "/v2/admin/challs/%s/instance" % challenge, token)
        state, endpoints = created["data"]["status"], created["data"].get("endpoints") or []
        # 300s covers the largest configured bootTimeoutSeconds (180) plus
        # the rootfs copy and readiness polling margin.
        deadline = time.monotonic() + 300
        while state not in ("running", "errored") and time.monotonic() < deadline:
            time.sleep(3)
            status = call("GET", "/v2/admin/challs/%s/instance" % challenge, token)
            state, endpoints = status["data"]["status"], status["data"].get("endpoints") or []
        print(json.dumps({"id": challenge, "state": state,
                          "seconds": round(time.monotonic() - started),
                          "endpoints": [{"kind": e.get("kind"), "host": e.get("host"),
                                         "port": e.get("port")} for e in endpoints]}))
    except Exception as error:  # noqa: BLE001 - report, keep launching the rest
        print(json.dumps({"id": challenge, "state": "ERROR", "detail": type(error).__name__}))
REMOTE
    cat >"$work/accept-cleanup.py" <<'REMOTE'
import json, sys, time, urllib.error, urllib.request

API = "http://127.0.0.1:8080/api"
ids = sys.argv[1:]

def call(method, path, token=None, data=None, timeout=30):
    body = json.dumps(data).encode() if data is not None else None
    request = urllib.request.Request(API + path, method=method, data=body)
    if body is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)

with open("/home/rctf-data/application/admin-team-token") as stream:
    team_token = stream.read().strip()
login = call("POST", "/v1/auth/login", data={"teamToken": team_token}, timeout=15)
assert login["kind"] == "goodLogin", "admin login was refused"
token = login["data"]["authToken"]

failed = 0
for challenge in ids:
    try:
        call("DELETE", "/v2/admin/challs/%s/instance" % challenge, token)
        deadline = time.monotonic() + 60
        gone = False
        while time.monotonic() < deadline:
            try:
                call("GET", "/v2/admin/challs/%s/instance" % challenge, token)
            except urllib.error.HTTPError:
                gone = True
                break
            time.sleep(3)
        if not gone:
            print(json.dumps({"id": challenge, "cleanup": "FAILED"}))
            failed += 1
        else:
            print(json.dumps({"id": challenge, "cleanup": "CONFIRMED"}))
    except Exception as error:  # noqa: BLE001
        print(json.dumps({"id": challenge, "cleanup": "FAILED", "detail": type(error).__name__}))
        failed += 1
sys.exit(1 if failed else 0)
REMOTE
    nuc_put "$work/accept-launch.py"
    nuc_put "$work/accept-cleanup.py"
    local launches=''
    if launches="$(nuc_root 'python3 /tmp/microlab-challenges-accept-launch.py' $ids)"; then
        launches="$(tr -d '\r' <<<"$launches")"
        echo "$launches" | sed 's/^/     /'
    else
        nuc_ssh 'rm -f /tmp/microlab-challenges-accept-launch.py /tmp/microlab-challenges-accept-cleanup.py' || true
        rm -rf "$work"
        die "the launch phase failed on the rCTF host"
    fi

    note "accept: probing every advertised endpoint from the controller (the player side of DNAT)"
    local failures=0 total=0
    while read -r line; do
        [ -n "$line" ] || continue
        total=$((total + 1))
        local id state seconds endpoints
        id="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["id"])' "$line")"
        state="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["state"])' "$line")"
        seconds="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("seconds","-"))' "$line")"
        endpoints="$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]).get("endpoints",[])))' "$line")"
        if [ "$state" != "running" ]; then
            echo "  FAIL $id: instance state $state"
            failures=$((failures + 1))
            continue
        fi
        local verdicts=''
        while read -r kind host port; do
            if [ "$kind" = "http" ] || [ "$kind" = "https" ]; then
                local marker body status_code
                marker="$(challenge_marker "$id")"
                body="$(curl -s --max-time 12 -o /dev/null -w '%{http_code}' --resolve "$host:80:$NUC_ADDRESS" -H "Host: $host" "http://$host/")" \
                    && status_code="$body" || status_code="no-response"
                body="$(curl -s --max-time 12 --resolve "$host:80:$NUC_ADDRESS" -H "Host: $host" "http://$host/")" || body=''
                if [ -n "$marker" ] && grep -qF "$marker" <<<"$body"; then
                    verdicts="$verdicts http $host reachable+themed(${status_code});"
                else
                    verdicts="$verdicts http $host FAILED(${status_code});"
                fi
            elif [ "$kind" = "tcp" ] || [ "$kind" = "raw" ]; then
                local banner=''
                banner="$(timeout 8 bash -c "exec 3<>/dev/tcp/$host/$port; head -c 16 <&3" 2>/dev/null || true)"
                if grep -q '^SSH-' <<<"$banner"; then
                    verdicts="$verdicts tcp $host:$port reachable+SSH-banner;"
                else
                    verdicts="$verdicts tcp $host:$port FAILED(no SSH banner);"
                fi
            fi
        done < <(python3 -c 'import json,sys
for e in json.loads(sys.argv[1]):
    print(e["kind"], e["host"], e["port"])' "$endpoints")
        if grep -q 'FAILED' <<<"$verdicts" || [ -z "$verdicts" ]; then
            echo "  FAIL $id: running in ${seconds}s but ${verdicts:-no endpoints}"
            failures=$((failures + 1))
        else
            echo "  PASS $id: running in ${seconds}s; $verdicts"
        fi
    done <<<"$launches"

    note "accept: deleting every launched instance and verifying teardown (one sudo prompt)"
    local cleanup
    if ! cleanup="$(nuc_root 'python3 /tmp/microlab-challenges-accept-cleanup.py' $ids)"; then
        nuc_ssh 'rm -f /tmp/microlab-challenges-accept-launch.py /tmp/microlab-challenges-accept-cleanup.py' || true
        rm -rf "$work"
        die "the cleanup phase failed on the rCTF host"
    fi
    cleanup="$(tr -d '\r' <<<"$cleanup")"
    echo "$cleanup" | sed 's/^/     /'
    nuc_ssh 'rm -f /tmp/microlab-challenges-accept-launch.py /tmp/microlab-challenges-accept-cleanup.py'
    rm -rf "$work"
    grep -q 'FAILED' <<<"$cleanup" && die "instance cleanup did not converge"
    grep -q 'CONFIRMED' <<<"$cleanup" || die "no cleanup confirmations were produced"
    echo "     all launched instances deleted and verified gone"

    if [ "$failures" -gt 0 ] || [ "$total" -lt 5 ]; then
        die "acceptance failed ($failures/$total endpoints); the deployment is NOT accepted"
    fi
    echo "     ACCEPT: $total/$total challenges launched, reached running, answered correctly"
}

run_stage() {
    # Every stage may need the host facts; the read is a cheap local parse.
    read_inventory_hosts
    case "$1" in
        preflight) stage_preflight ;;
        flags) stage_flags ;;
        artifacts) stage_artifacts ;;
        dns) stage_dns ;;
        caddy) stage_caddy ;;
        deploy) stage_deploy ;;
        accept) stage_accept ;;
        *) die "unknown stage: $1 (preflight|flags|artifacts|dns|caddy|deploy|accept)" ;;
    esac
}

if [ "$STAGE" = "all" ]; then
    for one in preflight flags artifacts dns caddy deploy accept; do
        run_stage "$one"
    done
    note "complete: challenge deployment finished. Acceptance above is what ran;"
    echo "     player-network vantages and event settings (startTime/endTime,"
    echo "     registrationsEnabled) remain operator work per docs/challenges.md."
else
    run_stage "$STAGE"
fi
